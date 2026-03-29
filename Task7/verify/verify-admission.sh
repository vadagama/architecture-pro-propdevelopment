#!/bin/bash
# verify-admission.sh — Проверка работы PodSecurity Admission Controller
# Скрипт пытается применить небезопасные манифесты и проверяет, что они отклоняются

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TASK_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Проверка PodSecurity Admission Controller ==="
echo ""

# 1. Проверяем что namespace audit-zone существует с правильными метками
echo "1. Проверка namespace audit-zone..."
NS_LABELS=$(kubectl get namespace audit-zone -o jsonpath='{.metadata.labels}' 2>/dev/null || true)
if echo "$NS_LABELS" | grep -q "restricted"; then
    echo -e "   ${GREEN}[OK]${NC} Namespace audit-zone существует с уровнем restricted"
else
    echo -e "   ${RED}[FAIL]${NC} Namespace audit-zone не найден или не имеет уровня restricted"
    echo "   Применяем namespace..."
    kubectl apply -f "$TASK_DIR/01-create-namespace.yaml"
fi
echo ""

# 2. Попытка применить небезопасные манифесты (должны быть отклонены)
echo "2. Проверка отклонения небезопасных манифестов..."

INSECURE_DIR="$TASK_DIR/insecure-manifests"
FAIL_COUNT=0
TOTAL=0

for manifest in "$INSECURE_DIR"/*.yaml; do
    TOTAL=$((TOTAL + 1))
    filename=$(basename "$manifest")
    echo -n "   Применяем $filename... "

    if kubectl apply -f "$manifest" 2>&1 | grep -qi "forbidden\|denied\|error\|warning"; then
        echo -e "${GREEN}[ОТКЛОНЕНО — OK]${NC}"
    else
        echo -e "${RED}[ПРИНЯТО — FAIL]${NC}"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        # Удаляем под, если он был создан
        POD_NAME=$(grep -oP 'name:\s*\K\S+' "$manifest" | head -1)
        kubectl delete pod "$POD_NAME" -n audit-zone --ignore-not-found >/dev/null 2>&1
    fi
done
echo ""

# 3. Попытка применить безопасные манифесты (должны быть приняты)
echo "3. Проверка принятия безопасных манифестов..."

SECURE_DIR="$TASK_DIR/secure-manifests"
PASS_COUNT=0
TOTAL_SECURE=0

for manifest in "$SECURE_DIR"/*.yaml; do
    TOTAL_SECURE=$((TOTAL_SECURE + 1))
    filename=$(basename "$manifest")
    echo -n "   Применяем $filename... "

    if kubectl apply -f "$manifest" 2>/dev/null; then
        echo -e "${GREEN}[ПРИНЯТО — OK]${NC}"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo -e "${RED}[ОТКЛОНЕНО — FAIL]${NC}"
    fi
done
echo ""

# 4. Очистка тестовых подов
echo "4. Очистка тестовых подов..."
kubectl delete pods --all -n audit-zone --ignore-not-found >/dev/null 2>&1
echo -e "   ${GREEN}[OK]${NC} Тестовые поды удалены"
echo ""

# Итоги
echo "=== Результаты ==="
echo "Небезопасные манифесты отклонены: $((TOTAL - FAIL_COUNT))/$TOTAL"
echo "Безопасные манифесты приняты: $PASS_COUNT/$TOTAL_SECURE"

if [ "$FAIL_COUNT" -eq 0 ] && [ "$PASS_COUNT" -eq "$TOTAL_SECURE" ]; then
    echo -e "${GREEN}Все проверки пройдены!${NC}"
    exit 0
else
    echo -e "${RED}Некоторые проверки не пройдены.${NC}"
    exit 1
fi
