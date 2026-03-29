#!/bin/bash
# Скрипт для создания пользователей Kubernetes через механизм CSR (CertificateSigningRequest).
# Создаёт приватный ключ, CSR и подписывает сертификат средствами Kubernetes.
# После этого настраивает kubeconfig для каждого пользователя.

set -euo pipefail

CLUSTER_NAME="minikube"

# Создаём директорию для хранения сертификатов пользователей
mkdir -p certs

create_user() {
  local USERNAME=$1
  local GROUP=$2

  echo "=== Создание пользователя: $USERNAME (группа: $GROUP) ==="

  # 1. Генерация приватного ключа
  openssl genrsa -out "certs/${USERNAME}.key" 2048

  # 2. Создание запроса на подпись сертификата (CSR)
  #    CN= задаёт имя пользователя, O= задаёт группу для RBAC
  openssl req -new -key "certs/${USERNAME}.key" \
    -out "certs/${USERNAME}.csr" \
    -subj "/CN=${USERNAME}/O=${GROUP}"

  # 3. Кодируем CSR в base64
  CSR_BASE64=$(cat "certs/${USERNAME}.csr" | base64 | tr -d '\n')

  # 4. Создаём манифест CertificateSigningRequest
  cat > "certs/${USERNAME}-csr.yaml" <<EOF
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: ${USERNAME}-csr
spec:
  request: ${CSR_BASE64}
  signerName: kubernetes.io/kube-apiserver-client
  usages:
    - client auth
EOF

  # 5. Применяем CSR в кластере
  kubectl apply -f "certs/${USERNAME}-csr.yaml"

  # 6. Одобряем CSR
  kubectl certificate approve "${USERNAME}-csr"

  # 7. Получаем подписанный сертификат
  kubectl get csr "${USERNAME}-csr" -o jsonpath='{.status.certificate}' | base64 -d > "certs/${USERNAME}.crt"

  # 8. Настраиваем kubeconfig для пользователя
  kubectl config set-credentials "${USERNAME}" \
    --client-certificate="certs/${USERNAME}.crt" \
    --client-key="certs/${USERNAME}.key"

  kubectl config set-context "${USERNAME}-context" \
    --cluster="${CLUSTER_NAME}" \
    --user="${USERNAME}"

  echo "Пользователь ${USERNAME} успешно создан."
  echo ""
}

# --- Создание пользователей ---

# Пользователь 1: DevOps-инженер (группа devops — привилегированный доступ)
create_user "devops-engineer-ivanov" "devops"

# Пользователь 2: Разработчик (группа developers — редактирование ресурсов в неймспейсах)
create_user "developer-petrov" "developers"

# Пользователь 3: Бизнес-аналитик (группа viewers — только просмотр)
create_user "analyst-sidorova" "viewers"

# Пользователь 4: Специалист по ИБ (группа security — привилегированный доступ)
create_user "security-kuznetsov" "security"

echo "=== Все пользователи созданы ==="
echo "Для переключения контекста используйте:"
echo "  kubectl config use-context <username>-context"
