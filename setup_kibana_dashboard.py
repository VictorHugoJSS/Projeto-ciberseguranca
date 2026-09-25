#!/usr/bin/env python3
"""
setup_kibana_dashboard.py
=========================
Cria automaticamente no Kibana:
  1. Data Views para os índices siem-syslog-*, siem-alerts-*, siem-generic-*
  2. Um dashboard completo de SSH Brute Force Detection pronto para a apresentação

Uso:
    python setup_kibana_dashboard.py

    # Caso sua senha seja diferente ou a porta seja outra:
    python setup_kibana_dashboard.py --kibana-url https://localhost:5601 --password SUA_SENHA
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.error
import ssl
import uuid

# ---------------------------------------------------------------------------
# Configuração padrão — altere se necessário
# ---------------------------------------------------------------------------
DEFAULT_KIBANA_URL = "https://localhost:5601"
DEFAULT_USER       = "elastic"
DEFAULT_PASSWORD   = "changeme"   # mesma do .env (ELASTIC_PASSWORD)

# UUIDs fixos para podermos referenciar entre objetos
DV_SYSLOG_ID  = "siem-dv-syslog"
DV_ALERTS_ID  = "siem-dv-alerts"
DV_ALL_ID     = "siem-dv-all"
DASHBOARD_ID  = "siem-ssh-bruteforce-dashboard"

# ---------------------------------------------------------------------------
# Helper HTTP (sem dependências externas)
# ---------------------------------------------------------------------------

def make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def api(method, path, body, kibana_url, user, password):
    url = kibana_url.rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    import base64
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    headers = {
        "Authorization": f"Basic {token}",
        "Content-Type":  "application/json",
        "kbn-xsrf":      "true",
    }
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=make_ctx(), timeout=30) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body_err = e.read().decode(errors="replace")
        return e.code, body_err


def wait_kibana(kibana_url, user, password, retries=30):
    print("⏳ Aguardando Kibana ficar disponível...", end="", flush=True)
    for i in range(retries):
        status, _ = api("GET", "/api/status", None, kibana_url, user, password)
        if status == 200:
            print(" OK!")
            return True
        print(".", end="", flush=True)
        time.sleep(5)
    print("\n❌ Kibana não respondeu.")
    return False


# ---------------------------------------------------------------------------
# 1. Data Views
# ---------------------------------------------------------------------------

def create_data_view(dv_id, title, time_field, kibana_url, user, password):
    payload = {
        "data_view": {
            "id":         dv_id,
            "title":      title,
            "timeFieldName": time_field,
        },
        "override": True,   # sobrescreve se já existir
    }
    status, resp = api("POST", "/api/data_views/data_view", payload, kibana_url, user, password)
    if status in (200, 201):
        print(f"   ✅ Data View '{title}' criado (id={dv_id})")
    else:
        print(f"   ⚠️  Data View '{title}': status={status}  {resp}")


# ---------------------------------------------------------------------------
# 2. Dashboard via Saved Objects bulk import
# ---------------------------------------------------------------------------

def build_saved_objects(dv_syslog_id, dv_alerts_id):
    """
    Retorna a lista de saved objects que compõem o dashboard.
    Inclui visualizações individuais e o próprio dashboard.
    """

    # ── Lens: Linha do tempo — todos os eventos syslog ───────────────────────
    lens_timeline = {
        "id": "siem-lens-timeline",
        "type": "lens",
        "attributes": {
            "title": "Linha do tempo — eventos syslog",
            "visualizationType": "lnsXY",
            "state": {
                "datasourceStates": {
                    "formBased": {
                        "layers": {
                            "layer1": {
                                "columnOrder": ["col_time", "col_count"],
                                "columns": {
                                    "col_time": {
                                        "dataType": "date",
                                        "isBucketed": True,
                                        "label": "@timestamp",
                                        "operationType": "date_histogram",
                                        "params": {"interval": "auto"},
                                        "sourceField": "@timestamp",
                                    },
                                    "col_count": {
                                        "dataType": "number",
                                        "isBucketed": False,
                                        "label": "Contagem",
                                        "operationType": "count",
                                        "sourceField": "___records___",
                                    },
                                },
                            }
                        }
                    }
                },
                "filters": [],
                "query": {"language": "kuery", "query": ""},
                "visualization": {
                    "axisTitlesVisibilitySettings": {"x": True, "yLeft": True},
                    "layers": [
                        {
                            "accessors": ["col_count"],
                            "layerId": "layer1",
                            "layerType": "data",
                            "seriesType": "bar_stacked",
                            "xAccessor": "col_time",
                        }
                    ],
                    "legend": {"isVisible": True, "position": "right"},
                    "preferredSeriesType": "bar_stacked",
                },
            },
            "references": [{"id": dv_syslog_id, "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}],
        },
        "references": [{"id": dv_syslog_id, "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}],
    }

    # ── Lens: Contagem de falhas SSH por IP ──────────────────────────────────
    lens_failed_by_ip = {
        "id": "siem-lens-failed-by-ip",
        "type": "lens",
        "attributes": {
            "title": "Falhas SSH por IP de origem",
            "visualizationType": "lnsXY",
            "state": {
                "datasourceStates": {
                    "formBased": {
                        "layers": {
                            "layer1": {
                                "columnOrder": ["col_ip", "col_count"],
                                "columns": {
                                    "col_ip": {
                                        "dataType": "string",
                                        "isBucketed": True,
                                        "label": "IP de origem",
                                        "operationType": "terms",
                                        "params": {"orderBy": {"columnId": "col_count", "type": "column"}, "orderDirection": "desc", "size": 10},
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
                            }
                        }
                    }
                },
                "filters": [{"meta": {"type": "phrase", "key": "event.outcome", "alias": None, "disabled": False, "negate": False, "params": {"query": "failure"}}, "query": {"match_phrase": {"event.outcome": "failure"}}}],
                "query": {"language": "kuery", "query": "event.action: ssh_login"},
                "visualization": {
                    "layers": [
                        {
                            "accessors": ["col_count"],
                            "layerId": "layer1",
                            "layerType": "data",
                            "seriesType": "bar",
                            "xAccessor": "col_ip",
                        }
                    ],
                    "legend": {"isVisible": False},
                    "preferredSeriesType": "bar",
                    "valueLabels": "inside",
                },
            },
            "references": [{"id": dv_alerts_id, "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}],
        },
        "references": [{"id": dv_alerts_id, "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}],
    }

    # ── Lens: Pie — sucesso vs falha ─────────────────────────────────────────
    lens_outcome_pie = {
        "id": "siem-lens-outcome-pie",
        "type": "lens",
        "attributes": {
            "title": "Resultado das tentativas SSH",
            "visualizationType": "lnsPie",
            "state": {
                "datasourceStates": {
                    "formBased": {
                        "layers": {
                            "layer1": {
                                "columnOrder": ["col_outcome", "col_count"],
                                "columns": {
                                    "col_outcome": {
                                        "dataType": "string",
                                        "isBucketed": True,
                                        "label": "Resultado",
                                        "operationType": "terms",
                                        "params": {"orderBy": {"columnId": "col_count", "type": "column"}, "orderDirection": "desc", "size": 10},
                                        "sourceField": "event.outcome",
                                    },
                                    "col_count": {
                                        "dataType": "number",
                                        "isBucketed": False,
                                        "label": "Eventos",
                                        "operationType": "count",
                                        "sourceField": "___records___",
                                    },
                                },
                            }
                        }
                    }
                },
                "filters": [],
                "query": {"language": "kuery", "query": "event.action: ssh_login"},
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
            "references": [{"id": dv_alerts_id, "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}],
        },
        "references": [{"id": dv_alerts_id, "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}],
    }

    # ── Metric: Total de falhas de autenticação ──────────────────────────────
    lens_total_failures = {
        "id": "siem-lens-total-failures",
        "type": "lens",
        "attributes": {
            "title": "Total de falhas SSH",
            "visualizationType": "lnsMetric",
            "state": {
                "datasourceStates": {
                    "formBased": {
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
                            }
                        }
                    }
                },
                "filters": [{"meta": {"type": "phrase", "key": "event.outcome", "alias": None, "disabled": False, "negate": False, "params": {"query": "failure"}}, "query": {"match_phrase": {"event.outcome": "failure"}}}],
                "query": {"language": "kuery", "query": "event.action: ssh_login"},
                "visualization": {
                    "layerId": "layer1",
                    "layerType": "data",
                    "metricAccessor": "col_count",
                },
            },
            "references": [{"id": dv_alerts_id, "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}],
        },
        "references": [{"id": dv_alerts_id, "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}],
    }

    # ── Metric: Ataques de brute force detectados ────────────────────────────
    lens_bruteforce_count = {
        "id": "siem-lens-bruteforce-count",
        "type": "lens",
        "attributes": {
            "title": "⚠️ Ataques Brute Force Detectados",
            "visualizationType": "lnsMetric",
            "state": {
                "datasourceStates": {
                    "formBased": {
                        "layers": {
                            "layer1": {
                                "columnOrder": ["col_count"],
                                "columns": {
                                    "col_count": {
                                        "dataType": "number",
                                        "isBucketed": False,
                                        "label": "Alertas",
                                        "operationType": "count",
                                        "sourceField": "___records___",
                                    }
                                },
                            }
                        }
                    }
                },
                "filters": [],
                "query": {"language": "kuery", "query": 'tags: "ssh_bruteforce_detected"'},
                "visualization": {
                    "layerId": "layer1",
                    "layerType": "data",
                    "metricAccessor": "col_count",
                },
            },
            "references": [{"id": dv_alerts_id, "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}],
        },
        "references": [{"id": dv_alerts_id, "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}],
    }

    # ── Metric: Logins SSH bem-sucedidos ─────────────────────────────────────
    lens_success_count = {
        "id": "siem-lens-success-count",
        "type": "lens",
        "attributes": {
            "title": "✅ Logins SSH Bem-sucedidos",
            "visualizationType": "lnsMetric",
            "state": {
                "datasourceStates": {
                    "formBased": {
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
                            }
                        }
                    }
                },
                "filters": [],
                "query": {"language": "kuery", "query": 'tags: "ssh_login_success"'},
                "visualization": {
                    "layerId": "layer1",
                    "layerType": "data",
                    "metricAccessor": "col_count",
                },
            },
            "references": [{"id": dv_alerts_id, "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}],
        },
        "references": [{"id": dv_alerts_id, "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}],
    }

    # ── Lens: Tabela — log de eventos SSH ────────────────────────────────────
    lens_event_table = {
        "id": "siem-lens-event-table",
        "type": "lens",
        "attributes": {
            "title": "Log de eventos SSH",
            "visualizationType": "lnsDatatable",
            "state": {
                "datasourceStates": {
                    "formBased": {
                        "layers": {
                            "layer1": {
                                "columnOrder": ["col_time", "col_outcome", "col_user", "col_ip", "col_count"],
                                "columns": {
                                    "col_time": {
                                        "dataType": "date",
                                        "isBucketed": True,
                                        "label": "Hora",
                                        "operationType": "date_histogram",
                                        "params": {"interval": "auto"},
                                        "sourceField": "@timestamp",
                                    },
                                    "col_outcome": {
                                        "dataType": "string",
                                        "isBucketed": True,
                                        "label": "Resultado",
                                        "operationType": "terms",
                                        "params": {"orderBy": {"columnId": "col_count", "type": "column"}, "orderDirection": "desc", "size": 10},
                                        "sourceField": "event.outcome",
                                    },
                                    "col_user": {
                                        "dataType": "string",
                                        "isBucketed": True,
                                        "label": "Usuário",
                                        "operationType": "terms",
                                        "params": {"orderBy": {"columnId": "col_count", "type": "column"}, "orderDirection": "desc", "size": 10},
                                        "sourceField": "user.name",
                                    },
                                    "col_ip": {
                                        "dataType": "string",
                                        "isBucketed": True,
                                        "label": "IP Atacante",
                                        "operationType": "terms",
                                        "params": {"orderBy": {"columnId": "col_count", "type": "column"}, "orderDirection": "desc", "size": 10},
                                        "sourceField": "source.ip",
                                    },
                                    "col_count": {
                                        "dataType": "number",
                                        "isBucketed": False,
                                        "label": "Eventos",
                                        "operationType": "count",
                                        "sourceField": "___records___",
                                    },
                                },
                            }
                        }
                    }
                },
                "filters": [],
                "query": {"language": "kuery", "query": "event.action: ssh_login"},
                "visualization": {
                    "columns": [
                        {"columnId": "col_time"},
                        {"columnId": "col_outcome"},
                        {"columnId": "col_user"},
                        {"columnId": "col_ip"},
                        {"columnId": "col_count"},
                    ],
                    "layerId": "layer1",
                    "layerType": "data",
                },
            },
            "references": [{"id": dv_alerts_id, "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}],
        },
        "references": [{"id": dv_alerts_id, "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}],
    }

    # ── Dashboard montando todos os painéis ──────────────────────────────────
    # Layout em grid: cada célula tem x, y, w, h em unidades de ~96px
    dashboard = {
        "id": DASHBOARD_ID,
        "type": "dashboard",
        "attributes": {
            "title": "🔐 SIEM — SSH Brute Force Detection",
            "description": "Dashboard de detecção de força bruta SSH em tempo real. Abra a apresentação, rode o simulate_bruteforce.py e veja os alertas aparecerem.",
            "timeRestore": False,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"language": "kuery", "query": ""},
                    "filter": [],
                })
            },
            "optionsJSON": json.dumps({
                "hidePanelTitles": False,
                "useMargins": True,
                "syncColors": False,
                "syncCursor": True,
                "syncTooltips": False,
            }),
            "panelsJSON": json.dumps([
                # Linha 1 — métricas de resumo (3 colunas)
                {"panelIndex": "p1", "gridData": {"x": 0,  "y": 0, "w": 16, "h": 8, "i": "p1"}, "embeddableConfig": {"title": "⚠️ Ataques Brute Force Detectados"}, "panelRefName": "panel_1"},
                {"panelIndex": "p2", "gridData": {"x": 16, "y": 0, "w": 16, "h": 8, "i": "p2"}, "embeddableConfig": {"title": "Total de falhas SSH"},               "panelRefName": "panel_2"},
                {"panelIndex": "p3", "gridData": {"x": 32, "y": 0, "w": 16, "h": 8, "i": "p3"}, "embeddableConfig": {"title": "✅ Logins SSH Bem-sucedidos"},         "panelRefName": "panel_3"},
                # Linha 2 — linha do tempo + pizza
                {"panelIndex": "p4", "gridData": {"x": 0,  "y": 8, "w": 32, "h": 15, "i": "p4"}, "embeddableConfig": {}, "panelRefName": "panel_4"},
                {"panelIndex": "p5", "gridData": {"x": 32, "y": 8, "w": 16, "h": 15, "i": "p5"}, "embeddableConfig": {}, "panelRefName": "panel_5"},
                # Linha 3 — bar chart + tabela
                {"panelIndex": "p6", "gridData": {"x": 0,  "y": 23, "w": 20, "h": 15, "i": "p6"}, "embeddableConfig": {}, "panelRefName": "panel_6"},
                {"panelIndex": "p7", "gridData": {"x": 20, "y": 23, "w": 28, "h": 15, "i": "p7"}, "embeddableConfig": {}, "panelRefName": "panel_7"},
            ]),
            "refreshInterval": {"pause": False, "value": 10000},   # auto-refresh 10s
            "timeFrom": "now-1h",
            "timeTo":   "now",
        },
        "references": [
            {"id": "siem-lens-bruteforce-count", "name": "panel_1", "type": "lens"},
            {"id": "siem-lens-total-failures",   "name": "panel_2", "type": "lens"},
            {"id": "siem-lens-success-count",    "name": "panel_3", "type": "lens"},
            {"id": "siem-lens-timeline",         "name": "panel_4", "type": "lens"},
            {"id": "siem-lens-outcome-pie",      "name": "panel_5", "type": "lens"},
            {"id": "siem-lens-failed-by-ip",     "name": "panel_6", "type": "lens"},
            {"id": "siem-lens-event-table",      "name": "panel_7", "type": "lens"},
        ],
    }

    return [
        lens_bruteforce_count,
        lens_total_failures,
        lens_success_count,
        lens_timeline,
        lens_outcome_pie,
        lens_failed_by_ip,
        lens_event_table,
        dashboard,
    ]


def import_saved_objects(objects, kibana_url, user, password):
    payload = {"objects": objects}
    status, resp = api(
        "POST",
        "/api/saved_objects/_import?overwrite=true",
        None,
        kibana_url, user, password,
    )
    # A API de import usa multipart — usamos a versão bulk create como fallback
    # Fazemos o import objeto a objeto via _bulk_create
    errors = []
    for obj in objects:
        s, r = api(
            "POST",
            f"/api/saved_objects/{obj['type']}/{obj['id']}?overwrite=true",
            {"attributes": obj["attributes"], "references": obj.get("references", [])},
            kibana_url, user, password,
        )
        if s in (200, 201):
            print(f"   ✅ {obj['type']:12s}  '{obj['attributes'].get('title', obj['id'])}'")
        else:
            print(f"   ❌ {obj['type']:12s}  '{obj['id']}' — {s}: {str(r)[:120]}")
            errors.append(obj["id"])
    return errors


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Configura Data Views e Dashboard no Kibana para demo de SSH Brute Force")
    parser.add_argument("--kibana-url", default=DEFAULT_KIBANA_URL)
    parser.add_argument("--user",       default=DEFAULT_USER)
    parser.add_argument("--password",   default=DEFAULT_PASSWORD)
    args = parser.parse_args()

    print(f"\n🔐 SIEM Dashboard Setup")
    print(f"   Kibana : {args.kibana_url}")
    print(f"   Usuário: {args.user}\n")

    if not wait_kibana(args.kibana_url, args.user, args.password):
        sys.exit(1)

    # ── Passo 1: Data Views ──────────────────────────────────────────────────
    print("\n📂 Criando Data Views...")
    create_data_view(DV_SYSLOG_ID,  "siem-syslog-*",  "@timestamp", args.kibana_url, args.user, args.password)
    create_data_view(DV_ALERTS_ID,  "siem-alerts-*",  "@timestamp", args.kibana_url, args.user, args.password)
    create_data_view(DV_ALL_ID,     "siem-*",         "@timestamp", args.kibana_url, args.user, args.password)

    # ── Passo 2: Visualizações + Dashboard ──────────────────────────────────
    print("\n📊 Importando visualizações e dashboard...")
    objects = build_saved_objects(DV_SYSLOG_ID, DV_ALERTS_ID)
    errors  = import_saved_objects(objects, args.kibana_url, args.user, args.password)

    print()
    if not errors:
        print("✅ Tudo criado com sucesso!\n")
        print("─" * 60)
        print(f"  Abra o Kibana → Dashboards")
        print(f"  Dashboard: 🔐 SIEM — SSH Brute Force Detection")
        print(f"\n  Depois rode o ataque:")
        print(f"    python simulate_bruteforce.py --attacker-ip 203.0.113.50 --attempts 8")
        print(f"\n  O dashboard atualiza automaticamente a cada 10s.")
        print("─" * 60)
    else:
        print(f"⚠️  Alguns objetos falharam: {errors}")
        print("   Verifique se o Kibana está rodando e se a senha está correta.")


if __name__ == "__main__":
    main()
