#!/bin/bash
# Скрипт для создания ролей RBAC в Kubernetes.
# Роли соответствуют таблице ROLES.md и принципу минимальных привилегий.
# Используются как ClusterRole (кластерный уровень), так и Role (уровень неймспейса).

set -euo pipefail

# Создаём директорию для YAML-манифестов
mkdir -p manifests

echo "=== Создание неймспейсов для доменов PropDevelopment ==="

# Неймспейсы соответствуют доменной структуре компании
kubectl create namespace sales --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace housing --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace finance --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace data --dry-run=client -o yaml | kubectl apply -f -

echo "Неймспейсы sales, housing, finance, data созданы."
echo ""

# --- 1. cluster-admin ---
# Встроенная ClusterRole cluster-admin уже существует в Kubernetes.
# Дополнительно создавать её не нужно.
echo "Роль cluster-admin: используется встроенная ClusterRole Kubernetes."

# --- 2. namespace-editor (ClusterRole) ---
# Позволяет управлять рабочими нагрузками, но не даёт доступ к Secrets и RBAC.
cat > manifests/namespace-editor-clusterrole.yaml <<'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: namespace-editor
rules:
- apiGroups: [""]
  resources: ["pods", "services", "configmaps", "persistentvolumeclaims", "endpoints", "serviceaccounts"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets", "statefulsets", "daemonsets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["batch"]
  resources: ["jobs", "cronjobs"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["networking.k8s.io"]
  resources: ["ingresses"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["autoscaling"]
  resources: ["horizontalpodautoscalers"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: [""]
  resources: ["pods/log", "events"]
  verbs: ["get", "list", "watch"]
EOF

kubectl apply -f manifests/namespace-editor-clusterrole.yaml
echo "ClusterRole namespace-editor создана."

# --- 3. namespace-viewer (ClusterRole) ---
# Доступ только на чтение. Без Secrets.
cat > manifests/namespace-viewer-clusterrole.yaml <<'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: namespace-viewer
rules:
- apiGroups: [""]
  resources: ["pods", "services", "configmaps", "persistentvolumeclaims", "endpoints", "serviceaccounts", "events", "pods/log"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets", "statefulsets", "daemonsets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["batch"]
  resources: ["jobs", "cronjobs"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["networking.k8s.io"]
  resources: ["ingresses"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["autoscaling"]
  resources: ["horizontalpodautoscalers"]
  verbs: ["get", "list", "watch"]
EOF

kubectl apply -f manifests/namespace-viewer-clusterrole.yaml
echo "ClusterRole namespace-viewer создана."

# --- 4. secret-manager (Role в каждом неймспейсе) ---
# Привилегированная роль: доступ к секретам. Создаётся на уровне неймспейса
# для более строгого контроля, аналогично примеру secret-reader из туториала.
for NS in sales housing finance data; do
  cat > "manifests/secret-manager-role-${NS}.yaml" <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: ${NS}
  name: secret-manager
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
EOF

  kubectl apply -f "manifests/secret-manager-role-${NS}.yaml"
  echo "Role secret-manager создана в неймспейсе ${NS}."
done

echo ""
echo "=== Все роли созданы ==="
echo "Проверка:"
echo "  kubectl get clusterroles | grep -E 'namespace-editor|namespace-viewer|cluster-admin'"
echo "  kubectl get roles --all-namespaces | grep secret-manager"
