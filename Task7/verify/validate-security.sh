#!/bin/bash
# validate-security.sh — Проверка OPA Gatekeeper и политик безопасности
# Скрипт проверяет что Gatekeeper установлен, шаблоны и ограничения активны

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TASK_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Валидация политик безопасности и OPA Gatekeeper ==="
echo ""

ERRORS=0

# 1. Проверяем наличие Gatekeeper
echo "1. Проверка установки OPA Gatekeeper..."
if kubectl get deployment gatekeeper-controller-manager -n gatekeeper-system >/dev/null 2>&1; then
    READY=$(kubectl get deployment gatekeeper-controller-manager -n gatekeeper-system \
        -o jsonpath='{.status.readyReplicas}' 2>/dev/null)
    echo -e "   ${GREEN}[OK]${NC} Gatekeeper установлен (ready replicas: ${READY:-0})"
else
    echo -e "   ${YELLOW}[WARN]${NC} Gatekeeper не установлен. Установите:"
    echo "   kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/v3.15.0/deploy/gatekeeper.yaml"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# 2. Проверяем ConstraintTemplates
echo "2. Проверка ConstraintTemplates..."
TEMPLATES=("k8spspprivilegedcontainer" "k8spsphostpath" "k8spsprunasnonroot")

for tmpl in "${TEMPLATES[@]}"; do
    if kubectl get constrainttemplate "$tmpl" >/dev/null 2>&1; then
        echo -e "   ${GREEN}[OK]${NC} ConstraintTemplate $tmpl существует"
    else
        echo -e "   ${RED}[FAIL]${NC} ConstraintTemplate $tmpl не найден"
        ERRORS=$((ERRORS + 1))
    fi
done
echo ""

# 3. Проверяем Constraints
echo "3. Проверка Constraints..."
CONSTRAINTS=(
    "k8spspprivilegedcontainer:deny-privileged-containers"
    "k8spsphostpath:deny-hostpath-volumes"
    "k8spsprunasnonroot:require-run-as-nonroot"
)

for entry in "${CONSTRAINTS[@]}"; do
    KIND="${entry%%:*}"
    NAME="${entry##*:}"
    if kubectl get "$KIND" "$NAME" >/dev/null 2>&1; then
        ENFORCEMENT=$(kubectl get "$KIND" "$NAME" -o jsonpath='{.spec.enforcementAction}' 2>/dev/null)
        echo -e "   ${GREEN}[OK]${NC} Constraint $NAME (enforcement: ${ENFORCEMENT:-deny})"
    else
        echo -e "   ${RED}[FAIL]${NC} Constraint $NAME не найден"
        ERRORS=$((ERRORS + 1))
    fi
done
echo ""

# 4. Проверяем PodSecurity Admission на namespace
echo "4. Проверка PodSecurity Admission..."
ENFORCE=$(kubectl get namespace audit-zone -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}' 2>/dev/null || true)
AUDIT=$(kubectl get namespace audit-zone -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/audit}' 2>/dev/null || true)
WARN=$(kubectl get namespace audit-zone -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/warn}' 2>/dev/null || true)

echo "   enforce: ${ENFORCE:-не задан}"
echo "   audit:   ${AUDIT:-не задан}"
echo "   warn:    ${WARN:-не задан}"

if [ "$ENFORCE" = "restricted" ]; then
    echo -e "   ${GREEN}[OK]${NC} PodSecurity enforce=restricted"
else
    echo -e "   ${RED}[FAIL]${NC} PodSecurity enforce != restricted"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# 5. Проверяем аудит нарушений в Gatekeeper
echo "5. Проверка аудита нарушений Gatekeeper..."
TOTAL_VIOLATIONS=0

for entry in "${CONSTRAINTS[@]}"; do
    KIND="${entry%%:*}"
    NAME="${entry##*:}"
    VIOLATIONS=$(kubectl get "$KIND" "$NAME" -o jsonpath='{.status.totalViolations}' 2>/dev/null || echo "N/A")
    echo "   $NAME: violations=$VIOLATIONS"
    if [ "$VIOLATIONS" != "N/A" ]; then
        TOTAL_VIOLATIONS=$((TOTAL_VIOLATIONS + VIOLATIONS))
    fi
done
echo ""

# Итоги
echo "=== Результаты валидации ==="
if [ "$ERRORS" -eq 0 ]; then
    echo -e "${GREEN}Все проверки пройдены! Политики безопасности активны.${NC}"
    exit 0
else
    echo -e "${RED}Обнаружено ошибок: $ERRORS${NC}"
    echo "Примените манифесты из gatekeeper/ и проверьте снова."
    exit 1
fi
