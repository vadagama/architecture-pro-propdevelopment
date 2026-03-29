#!/bin/bash
# Скрипт для привязки пользователей и групп к ролям.
# Используются ClusterRoleBinding (кластерный уровень) и RoleBinding (уровень неймспейса).
# Связывает пользователей, созданных в create-users.sh, с ролями из create-roles.sh.

set -euo pipefail

# Создаём директорию для YAML-манифестов
mkdir -p manifests

echo "=== Привязка ролей к пользователям и группам ==="

# --- 1. ClusterRoleBinding: cluster-admin для групп devops и security ---
# DevOps-инженеры и специалист по ИБ получают полный доступ к кластеру
cat > manifests/devops-cluster-admin-binding.yaml <<'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: devops-cluster-admin
subjects:
- kind: Group
  name: devops
  apiGroup: rbac.authorization.k8s.io
- kind: Group
  name: security
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
EOF

kubectl apply -f manifests/devops-cluster-admin-binding.yaml
echo "ClusterRoleBinding: cluster-admin привязана к группам devops, security."

# --- 2. ClusterRoleBinding: namespace-editor для группы developers ---
# Разработчики и инженеры по эксплуатации могут управлять рабочими нагрузками
cat > manifests/developers-editor-binding.yaml <<'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: developers-namespace-editor
subjects:
- kind: Group
  name: developers
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: namespace-editor
  apiGroup: rbac.authorization.k8s.io
EOF

kubectl apply -f manifests/developers-editor-binding.yaml
echo "ClusterRoleBinding: namespace-editor привязана к группе developers."

# --- 3. ClusterRoleBinding: namespace-viewer для группы viewers ---
# Бизнес-аналитики, менеджеры и владельцы продуктов — только просмотр
cat > manifests/viewers-viewer-binding.yaml <<'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: viewers-namespace-viewer
subjects:
- kind: Group
  name: viewers
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: namespace-viewer
  apiGroup: rbac.authorization.k8s.io
EOF

kubectl apply -f manifests/viewers-viewer-binding.yaml
echo "ClusterRoleBinding: namespace-viewer привязана к группе viewers."

# --- 4. RoleBinding: secret-manager в каждом неймспейсе для групп devops и security ---
# Доступ к секретам ограничен конкретными неймспейсами (принцип минимальных привилегий)
for NS in sales housing finance data; do
  cat > "manifests/secret-manager-binding-${NS}.yaml" <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: secret-manager-binding
  namespace: ${NS}
subjects:
- kind: Group
  name: devops
  apiGroup: rbac.authorization.k8s.io
- kind: Group
  name: security
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: secret-manager
  apiGroup: rbac.authorization.k8s.io
EOF

  kubectl apply -f "manifests/secret-manager-binding-${NS}.yaml"
  echo "RoleBinding: secret-manager привязана к группам devops, security в неймспейсе ${NS}."
done

echo ""
echo "=== Все привязки созданы ==="
echo "Проверка:"
echo "  kubectl get clusterrolebindings | grep -E 'devops-cluster-admin|developers-namespace-editor|viewers-namespace-viewer'"
echo "  kubectl get rolebindings --all-namespaces | grep secret-manager"
