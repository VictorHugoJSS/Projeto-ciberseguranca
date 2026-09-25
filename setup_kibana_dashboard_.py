#!/usr/bin/env python3
"""
setup_kibana_dashboard.py
=========================
Cria automaticamente no Kibana:
  1. Data Views para os indices siem-syslog-*, siem-alerts-*, siem-*
  2. Um dashboard completo de SSH Brute Force Detection

Uso:
    python setup_kibana_dashboard.py --kibana-url http://localhost:5601 --password SenhaElastic123!
"""

import argparse
import base64
import json
import sys
import time

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    import urllib.request
    import urllib.error
    import ssl

# ---------------------------------------------------------------------------
# Config padrao
# ---------------------------------------------------------------------------
DEFAULT_KIBANA_URL = "http://localhost:5601"
DEFAULT_USER       = "elastic"
DEFAULT_PASSWORD   = "SenhaElastic123!"

DV_ALL_ID     = "siem-dv-all"
DV_SYSLOG_ID  = "siem-dv-syslog"
DV_ALERTS_ID  = "siem-dv-alerts"

DEBUG_DUMP_PATH = "/tmp/kibana_bulk_create_payload.json"


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def auth_header(user, password):
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"Basic {token}"


def kibana_post(url, user, password, path, body=None, content_type="application/json"):
    full_url = url.rstrip("/") + path
    headers = {
        "Authorization": auth_header(user, password),
        "kbn-xsrf": "true",
    }
    if content_type:
        headers["Content-Type"] = content_type

    if HAS_REQUESTS:
        data = json.dumps(body).encode() if body is not None else None
        r = requests.post(full_url, headers=headers, data=data, verify=False, timeout=30)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, r.text
    else:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(full_url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace")


def kibana_get(url, user, password, path):
    full_url = url.rstrip("/") + path
    headers = {"Authorization": auth_header(user, password), "kbn-xsrf": "true"}
    if HAS_REQUESTS:
        r = requests.get(full_url, headers=headers, verify=False, timeout=30)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, r.text
    else:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(full_url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace")


# ---------------------------------------------------------------------------
# Aguarda Kibana
# ---------------------------------------------------------------------------

def wait_kibana(url, user, password, retries=30):
    print("[*] Aguardando Kibana ficar disponivel...", end="", flush=True)
    for _ in range(retries):
        try:
            status, _ = kibana_get(url, user, password, "/api/status")
            if status == 200:
                print(" OK!")
                return True
        except Exception:
            pass
        print(".", end="", flush=True)
        time.sleep(5)
    print("\n[ERRO] Kibana nao respondeu.")
    return False


# ---------------------------------------------------------------------------
# Data Views
# ---------------------------------------------------------------------------

def create_data_view(dv_id, title, time_field, url, user, password):
    payload = {
        "data_view": {
            "id": dv_id,
            "title": title,
            "timeFieldName": time_field,
        },
        "override": True,
    }
    status, resp = kibana_post(url, user, password, "/api/data_views/data_view", payload)
    if status in (200, 201):
        print(f"   [OK] Data View '{title}' (id={dv_id})")
    else:
        print(f"   [AVISO] Data View '{title}': status={status} resp={str(resp)[:300]}")


# ---------------------------------------------------------------------------
# Saved Objects via _bulk_create — endpoint mais previsivel que _import
# ---------------------------------------------------------------------------

def _strip_nested_references(attrs):
    """
    Salvaguarda: 'references' NUNCA pode existir dentro de 'attributes' (nem
    no nivel raiz de attributes, nem escondido em sub-objetos como 'state').
    Esse foi exatamente o motivo do erro 400 'Additional properties are not
    allowed (references)' — o Kibana so aceita 'references' como irmao de
    'attributes' no objeto raiz.
    """
    if not isinstance(attrs, dict):
        return attrs
    clean = {}
    for k, v in attrs.items():
        if k == "references":
            continue  # nunca deixa passar 'references' dentro de attributes
        clean[k] = v
    return clean


def bulk_create(objects, url, user, password):
    """
    Usa /api/saved_objects/_bulk_create, que recebe um array JSON simples
    (sem multipart/NDJSON) e valida attributes/references de forma mais
    clara que o endpoint _import.
    """
    body = []
    for obj in objects:
        body.append({
            "type": obj["type"],
            "id": obj["id"],
            "attributes": _strip_nested_references(obj["attributes"]),
            "references": obj.get("references", []),
        })

    # Dump de debug: se algo falhar de novo, dá pra inspecionar exatamente
    # o que foi enviado.
    try:
        with open(DEBUG_DUMP_PATH, "w", encoding="utf-8") as f:
            json.dump(body, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

    status, resp = kibana_post(
        url, user, password,
        "/api/saved_objects/_bulk_create?overwrite=true",
        body,
    )
    return status, resp


# ---------------------------------------------------------------------------
# Definicao dos Saved Objects (formato export do Kibana)
# ---------------------------------------------------------------------------

def build_objects(dv_syslog_id, dv_alerts_id):
    """
    Constroi todos os objetos no formato de exportacao do Kibana.
    Nenhum campo 'references' aparece dentro de 'attributes'.
    """

    # ── Timeline ─────────────────────────────────────────────────────────────
    lens_timeline = {
        "id": "siem-lens-timeline",
        "type": "lens",
        "attributes": {
            "title": "Timeline do Incidente",
            "visualizationType": "lnsXY",
            "state": {
                "datasourceStates": {
                    "formBased": {
                        "currentIndexPatternId": dv_alerts_id,
                        "layers": {
                            "layer1": {
                                "columnOrder": ["col_time", "col_tag", "col_count"],
                                "columns": {
                                    "col_time": {
                                        "dataType": "date",
                                        "isBucketed": True,
                                        "label": "@timestamp",
                                        "operationType": "date_histogram",
                                        "params": {"interval": "auto", "includeEmptyRows": True},
                                        "sourceField": "@timestamp",
                                    },
                                    "col_tag": {
                                        "dataType": "string",
                                        "isBucketed": True,
                                        "label": "Resultado",
                                        "operationType": "terms",
                                        "params": {
                                            "orderBy": {"type": "alphabetical"},
                                            "orderDirection": "asc",
                                            "size": 10,
                                            "otherBucket": False,
                                        },
                                        "sourceField": "event.outcome.keyword",
                                    },
                                    "col_count": {
                                        "dataType": "number",
                                        "isBucketed": False,
                                        "label": "Eventos",
                                        "operationType": "count",
                                        "sourceField": "___records___",
                                    },
                                },
                                "indexPatternId": dv_alerts_id,
                                "incompleteColumns": {},
                            }
                        }
                    }
                },
                "filters": [],
                "query": {"language": "kuery", "query": ""},
                "visualization": {
                    "layers": [
                        {
                            "accessors": ["col_count"],
                            "layerId": "layer1",
                            "layerType": "data",
                            "seriesType": "bar_stacked",
                            "splitAccessor": "col_tag",
                            "xAccessor": "col_time",
                        }
                    ],
                    "legend": {"isVisible": True, "position": "right"},
                    "preferredSeriesType": "bar_stacked",
                    "valueLabels": "hide",
                },
            },
        },
        "references": [
            {"id": dv_alerts_id, "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}
        ],
    }

    # ── Tentativas SSH por IP ─────────────────────────────────────────────────
    lens_failed_by_ip = {
        "id": "siem-lens-failed-by-ip",
        "type": "lens",
        "attributes": {
            "title": "Falhas SSH por IP de Origem",
            "visualizationType": "lnsXY",
            "state": {
                "datasourceStates": {
                    "formBased": {
                        "currentIndexPatternId": dv_alerts_id,
                        "layers": {
                            "layer1": {
                                "columnOrder": ["col_ip", "col_count"],
                                "columns": {
                                    "col_ip": {
                                        "dataType": "string",
                                        "isBucketed": True,
                                        "label": "IP de origem",
                                        "operationType": "terms",
                                        "params": {
                                            "orderBy": {"columnId": "col_count", "type": "column"},
                                            "orderDirection": "desc",
                                            "size": 10,
                                            "otherBucket": False,
                                        },
                                        "sourceField": "source.ip",
                                    },
                                    "col_count": {
                                        "dataType": "number",
                                        "isBucketed": False,
                                        "label": "Tentativas",
                                        "operationType": "count",
                                        "sourceField": "___records___",
                                    },
                                },
                                "indexPatternId": dv_alerts_id,
                                "incompleteColumns": {},
                            }
                        }
                    }
                },
                "filters": [
                    {
                        "meta": {"type": "phrase", "key": "event.outcome", "negate": False, "disabled": False, "params": {"query": "failure"}},
                        "query": {"match_phrase": {"event.outcome": "failure"}},
                    }
                ],
                "query": {"language": "kuery", "query": ""},
                "visualization": {
                    "layers": [
                        {
                            "accessors": ["col_count"],
                            "layerId": "layer1",
                            "layerType": "data",
                            "seriesType": "bar_horizontal",
                            "xAccessor": "col_ip",
                        }
                    ],
                    "legend": {"isVisible": False},
                    "preferredSeriesType": "bar_horizontal",
                },
            },
        },
        "references": [
            {"id": dv_alerts_id, "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}
        ],
    }

    # ── Pie: sucesso vs falha ─────────────────────────────────────────────────
    lens_outcome_pie = {
        "id": "siem-lens-outcome-pie",
        "type": "lens",
        "attributes": {
            "title": "Resultado das Tentativas SSH",
            "visualizationType": "lnsPie",
            "state": {
                "datasourceStates": {
                    "formBased": {
                        "currentIndexPatternId": dv_alerts_id,
                        "layers": {
                            "layer1": {
                                "columnOrder": ["col_outcome", "col_count"],
                                "columns": {
                                    "col_outcome": {
                                        "dataType": "string",
                                        "isBucketed": True,
                                        "label": "Resultado",
                                        "operationType": "terms",
                                        "params": {
                                            "orderBy": {"columnId": "col_count", "type": "column"},
                                            "orderDirection": "desc",
                                            "size": 5,
                                            "otherBucket": False,
                                        },
                                        "sourceField": "event.outcome.keyword",
                                    },
                                    "col_count": {
                                        "dataType": "number",
                                        "isBucketed": False,
                                        "label": "Eventos",
                                        "operationType": "count",
                                        "sourceField": "___records___",
                                    },
                                },
                                "indexPatternId": dv_alerts_id,
                                "incompleteColumns": {},
                            }
                        }
                    }
                },
                "filters": [],
                "query": {"language": "kuery", "query": ""},
                "visualization": {
                    "layers": [
                        {
                            "categoryDisplay": "default",
                            "groups": ["col_outcome"],
                            "layerId": "layer1",
                            "layerType": "data",
                            "legendDisplay": "default",
                            "metrics": ["col_count"],
                            "nestedLegend": False,
                            "numberDisplay": "percent",
                        }
                    ],
                    "shape": "pie",
                },
            },
        },
        "references": [
            {"id": dv_alerts_id, "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}
        ],
    }

    # ── Metric: Total falhas SSH ──────────────────────────────────────────────
    lens_total_failures = {
        "id": "siem-lens-total-failures",
        "type": "lens",
        "attributes": {
            "title": "Total de Falhas SSH",
            "visualizationType": "lnsMetric",
            "state": {
                "datasourceStates": {
                    "formBased": {
                        "currentIndexPatternId": dv_alerts_id,
                        "layers": {
                            "layer1": {
                                "columnOrder": ["col_count"],
                                "columns": {
                                    "col_count": {
                                        "dataType": "number",
                                        "isBucketed": False,
                                        "label": "Falhas",
                                        "operationType": "count",
                                        "sourceField": "___records___",
                                    }
                                },
                                "indexPatternId": dv_alerts_id,
                                "incompleteColumns": {},
                            }
                        }
                    }
                },
                "filters": [
                    {
                        "meta": {"type": "phrase", "key": "event.outcome", "negate": False, "disabled": False, "params": {"query": "failure"}},
                        "query": {"match_phrase": {"event.outcome": "failure"}},
                    }
                ],
                "query": {"language": "kuery", "query": ""},
                "visualization": {
                    "layerId": "layer1",
                    "layerType": "data",
                    "metricAccessor": "col_count",
                },
            },
        },
        "references": [
            {"id": dv_alerts_id, "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}
        ],
    }

    # ── Metric: Logins bem-sucedidos ─────────────────────────────────────────
    lens_success_count = {
        "id": "siem-lens-success-count",
        "type": "lens",
        "attributes": {
            "title": "Logins SSH Bem-sucedidos",
            "visualizationType": "lnsMetric",
            "state": {
                "datasourceStates": {
                    "formBased": {
                        "currentIndexPatternId": dv_alerts_id,
                        "layers": {
                            "layer1": {
                                "columnOrder": ["col_count"],
                                "columns": {
                                    "col_count": {
                                        "dataType": "number",
                                        "isBucketed": False,
                                        "label": "Logins",
                                        "operationType": "count",
                                        "sourceField": "___records___",
                                    }
                                },
                                "indexPatternId": dv_alerts_id,
                                "incompleteColumns": {},
                            }
                        }
                    }
                },
                "filters": [
                    {
                        "meta": {"type": "phrase", "key": "event.outcome", "negate": False, "disabled": False, "params": {"query": "success"}},
                        "query": {"match_phrase": {"event.outcome": "success"}},
                    }
                ],
                "query": {"language": "kuery", "query": ""},
                "visualization": {
                    "layerId": "layer1",
                    "layerType": "data",
                    "metricAccessor": "col_count",
                },
            },
        },
        "references": [
            {"id": dv_alerts_id, "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}
        ],
    }

    # ── Dashboard ─────────────────────────────────────────────────────────────
    dashboard = {
        "id": "siem-ssh-bruteforce-dashboard",
        "type": "dashboard",
        "attributes": {
            "title": "SIEM - SSH Brute Force Detection",
            "description": "Dashboard de deteccao de forca bruta SSH. Apresentacao academica.",
            "timeRestore": False,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({"query": {"language": "kuery", "query": ""}, "filter": []})
            },
            "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
            "panelsJSON": json.dumps([
                {"panelIndex": "p1", "gridData": {"x": 0,  "y": 0,  "w": 24, "h": 8,  "i": "p1"}, "embeddableConfig": {}, "panelRefName": "panel_1"},
                {"panelIndex": "p2", "gridData": {"x": 24, "y": 0,  "w": 24, "h": 8,  "i": "p2"}, "embeddableConfig": {}, "panelRefName": "panel_2"},
                {"panelIndex": "p3", "gridData": {"x": 0,  "y": 8,  "w": 48, "h": 16, "i": "p3"}, "embeddableConfig": {}, "panelRefName": "panel_3"},
                {"panelIndex": "p4", "gridData": {"x": 0,  "y": 24, "w": 24, "h": 14, "i": "p4"}, "embeddableConfig": {}, "panelRefName": "panel_4"},
                {"panelIndex": "p5", "gridData": {"x": 24, "y": 24, "w": 24, "h": 14, "i": "p5"}, "embeddableConfig": {}, "panelRefName": "panel_5"},
            ]),
            "refreshInterval": {"pause": False, "value": 10000},
            "timeFrom": "now-2h",
            "timeTo": "now",
        },
        "references": [
            {"id": "siem-lens-total-failures",  "name": "panel_1", "type": "lens"},
            {"id": "siem-lens-success-count",   "name": "panel_2", "type": "lens"},
            {"id": "siem-lens-timeline",        "name": "panel_3", "type": "lens"},
            {"id": "siem-lens-outcome-pie",     "name": "panel_4", "type": "lens"},
            {"id": "siem-lens-failed-by-ip",    "name": "panel_5", "type": "lens"},
        ],
    }

    return [
        lens_total_failures,
        lens_success_count,
        lens_timeline,
        lens_outcome_pie,
        lens_failed_by_ip,
        dashboard,
    ]


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kibana-url", default=DEFAULT_KIBANA_URL)
    parser.add_argument("--user",       default=DEFAULT_USER)
    parser.add_argument("--password",   default=DEFAULT_PASSWORD)
    args = parser.parse_args()

    print(f"\n[SIEM] Dashboard Setup")
    print(f"   Kibana  : {args.kibana_url}")
    print(f"   Usuario : {args.user}\n")

    if not wait_kibana(args.kibana_url, args.user, args.password):
        sys.exit(1)

    # Passo 1 — Data Views
    print("\n[1] Criando Data Views...")
    create_data_view(DV_SYSLOG_ID, "siem-syslog-*", "@timestamp", args.kibana_url, args.user, args.password)
    create_data_view(DV_ALERTS_ID, "siem-alerts-*", "@timestamp", args.kibana_url, args.user, args.password)
    create_data_view(DV_ALL_ID,    "siem-*",        "@timestamp", args.kibana_url, args.user, args.password)

    # Passo 2 — Criar objetos via _bulk_create
    print("\n[2] Importando visualizacoes e dashboard via _bulk_create...")
    objects = build_objects(DV_SYSLOG_ID, DV_ALERTS_ID)
    status, resp = bulk_create(objects, args.kibana_url, args.user, args.password)

    if status in (200, 201) and isinstance(resp, dict) and "saved_objects" in resp:
        failed = []
        for so in resp["saved_objects"]:
            oid = so.get("id", "?")
            err = so.get("error")
            if err:
                failed.append(oid)
                print(f"   [ERRO] {so.get('type','?'):<10} '{oid}' — {err.get('statusCode')}: {err.get('message')}")
            else:
                print(f"   [OK]   {so.get('type','?'):<10} '{oid}'")

        if failed:
            print(f"\n[AVISO] Alguns objetos falharam: {failed}")
            print(f"   Payload completo salvo em: {DEBUG_DUMP_PATH}")
        else:
            print("\n[CONCLUIDO] Tudo criado com sucesso!")
            print("\n   Abra: http://localhost:5601")
            print("   Menu > Analytics > Dashboards")
            print('   Abra: "SIEM - SSH Brute Force Detection"')
    else:
        print(f"\n[ERRO] Status {status}: {str(resp)[:500]}")
        print(f"   Payload completo salvo em: {DEBUG_DUMP_PATH}")
        print("   Verifique se o Kibana esta no ar e a senha esta correta.")


if __name__ == "__main__":
    main()
