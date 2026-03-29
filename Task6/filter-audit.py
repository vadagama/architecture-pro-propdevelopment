#!/usr/bin/env python3
"""
Скрипт фильтрации Kubernetes audit.log для обнаружения подозрительных событий.

Использование:
    python3 filter-audit.py /var/log/audit.log
    python3 filter-audit.py /var/log/audit.log --output audit-extract.json
"""

import json
import sys
import argparse
from typing import Any


def load_audit_log(path: str) -> list[dict[str, Any]]:
    """Загружает audit.log (формат — по одному JSON-объекту на строку)."""
    events = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


# ---------------------------------------------------------------------------
# Фильтры подозрительных событий
# ---------------------------------------------------------------------------

def is_secret_access(event: dict) -> bool:
    """Доступ к secrets (get/list)."""
    obj_ref = event.get("objectRef", {})
    return (
        obj_ref.get("resource") == "secrets"
        and event.get("verb") in ("get", "list")
    )


def is_privileged_pod(event: dict) -> bool:
    """Создание привилегированного пода."""
    obj_ref = event.get("objectRef", {})
    if obj_ref.get("resource") != "pods":
        return False
    if event.get("verb") not in ("create", "update", "patch"):
        return False
    req = event.get("requestObject", {})
    if not isinstance(req, dict):
        return False
    for container in req.get("spec", {}).get("containers", []):
        sc = container.get("securityContext", {})
        if sc.get("privileged") is True:
            return True
    return False


def is_exec_in_pod(event: dict) -> bool:
    """kubectl exec в поде (subresource=exec)."""
    obj_ref = event.get("objectRef", {})
    return (
        event.get("verb") == "create"
        and obj_ref.get("subresource") == "exec"
    )


def is_audit_policy_tampering(event: dict) -> bool:
    """Удаление или изменение audit-policy."""
    request_uri = event.get("requestURI", "")
    obj_name = event.get("objectRef", {}).get("name", "")
    combined = f"{request_uri} {obj_name}".lower()
    return "audit-policy" in combined or "audit" in obj_name.lower() and event.get("verb") in ("delete", "update", "patch")


def is_rolebinding_escalation(event: dict) -> bool:
    """Создание RoleBinding/ClusterRoleBinding с cluster-admin."""
    obj_ref = event.get("objectRef", {})
    if obj_ref.get("resource") not in ("rolebindings", "clusterrolebindings"):
        return False
    if event.get("verb") not in ("create", "update", "patch"):
        return False
    req = event.get("requestObject", {})
    if not isinstance(req, dict):
        return False
    role_ref = req.get("roleRef", {})
    return role_ref.get("name") == "cluster-admin"


def is_impersonation(event: dict) -> bool:
    """Использование impersonation (--as=...)."""
    user_info = event.get("impersonatedUser", {})
    return bool(user_info.get("username"))


# ---------------------------------------------------------------------------
# Классификация
# ---------------------------------------------------------------------------

FILTERS = [
    ("secret_access", "Доступ к секретам", is_secret_access),
    ("privileged_pod", "Создание привилегированного пода", is_privileged_pod),
    ("exec_in_pod", "kubectl exec в чужом поде", is_exec_in_pod),
    ("audit_policy_tampering", "Удаление/изменение audit-policy", is_audit_policy_tampering),
    ("rolebinding_escalation", "Эскалация через RoleBinding (cluster-admin)", is_rolebinding_escalation),
    ("impersonation", "Использование impersonation", is_impersonation),
]


def classify_event(event: dict) -> list[str]:
    """Возвращает список меток угроз для события."""
    tags = []
    for tag, _desc, fn in FILTERS:
        if fn(event):
            tags.append(tag)
    return tags


def extract_suspicious(events: list[dict]) -> list[dict]:
    """Отфильтровывает подозрительные события и добавляет метки."""
    suspicious = []
    for event in events:
        tags = classify_event(event)
        if tags:
            record = {
                "timestamp": event.get("requestReceivedTimestamp", event.get("stageTimestamp", "")),
                "verb": event.get("verb", ""),
                "user": event.get("user", {}).get("username", ""),
                "impersonatedUser": event.get("impersonatedUser", {}).get("username", ""),
                "resource": event.get("objectRef", {}).get("resource", ""),
                "namespace": event.get("objectRef", {}).get("namespace", ""),
                "name": event.get("objectRef", {}).get("name", ""),
                "subresource": event.get("objectRef", {}).get("subresource", ""),
                "responseCode": event.get("responseStatus", {}).get("code", ""),
                "tags": tags,
                "sourceIP": (event.get("sourceIPs") or [""])[0],
            }
            suspicious.append(record)
    return suspicious


def print_summary(suspicious: list[dict]) -> None:
    """Выводит краткую сводку в stdout."""
    print(f"\n{'='*60}")
    print(f"  Найдено подозрительных событий: {len(suspicious)}")
    print(f"{'='*60}\n")

    tag_counts: dict[str, int] = {}
    for rec in suspicious:
        for tag in rec["tags"]:
            tag_counts[tag] = tag_counts.get(tag, 0) + 1

    for tag, _desc, _fn in FILTERS:
        desc = _desc
        count = tag_counts.get(tag, 0)
        if count:
            print(f"  [{count:>3}]  {desc}")

    print()
    for i, rec in enumerate(suspicious, 1):
        user = rec["impersonatedUser"] or rec["user"]
        print(
            f"  {i:>3}. [{','.join(rec['tags'])}] "
            f"verb={rec['verb']}  user={user}  "
            f"resource={rec['resource']}/{rec['name']}  "
            f"ns={rec['namespace']}  code={rec['responseCode']}"
        )
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Фильтрация Kubernetes audit.log")
    parser.add_argument("audit_log", help="Путь к файлу audit.log")
    parser.add_argument(
        "--output", "-o",
        default="audit-extract.json",
        help="Путь для сохранения JSON с подозрительными событиями (по умолчанию: audit-extract.json)",
    )
    args = parser.parse_args()

    events = load_audit_log(args.audit_log)
    print(f"Загружено событий: {len(events)}")

    suspicious = extract_suspicious(events)
    print_summary(suspicious)

    with open(args.output, "w") as f:
        json.dump(suspicious, f, indent=2, ensure_ascii=False)
    print(f"Результат сохранён в {args.output}")


if __name__ == "__main__":
    main()
