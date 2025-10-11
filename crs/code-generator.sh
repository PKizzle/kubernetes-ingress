#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

# set client native version
client_native_version=$(go list -m -f "{{.Version}}" github.com/haproxytech/client-native/v6)
echo "Client Native Version: $client_native_version"
for file in crs/api/ingress/v3/*.go; do
    echo "$file"
	# Use sed to replace the version string in Go files with the new version
	# Check on which os the script is running and use the correct sed command (macOS uses a different syntax)
	if [[ "$OSTYPE" == "darwin"* ]]; then
		gsed -i "s@// +kubebuilder:metadata:annotations=\"haproxy.org/client-native=.*\"@// +kubebuilder:metadata:annotations=\"haproxy.org/client-native=$client_native_version\"@" $file
    else
    	sed -i "s@// +kubebuilder:metadata:annotations=\"haproxy.org/client-native=.*\"@// +kubebuilder:metadata:annotations=\"haproxy.org/client-native=$client_native_version\"@" $file
	fi
done

# code-generator build native, versioned clients, informers and other helpers
# via Kubernetes code generators from k8s.oi/code-generator

CR_DIR=$( cd -- "$( dirname -- "$( readlink -f -- "${BASH_SOURCE[0]}"; )" )" &> /dev/null && pwd )
OUTPUT_DIR="${CR_DIR}/generated"
HDR_FILE="$( readlink -f -- "${CR_DIR}/../assets/license-header.txt"; )"
CR_PKG="github.com/haproxytech/kubernetes-ingress/crs"
if [[ "$OSTYPE" == "darwin"* ]]; then
	API_PKGS=$(find "${CR_DIR}/api" -mindepth 2 -type d | gsed "s|^${CR_DIR}/api/|${CR_PKG}/api/|" | sort | tr '\n' ',' | gsed 's/,$//')
else
	API_PKGS=$(find "${CR_DIR}/api" -mindepth 2 -type d | sed "s|^${CR_DIR}/api/|${CR_PKG}/api/|" | sort | tr '\n' ',' | sed 's/,$//')
fi

# Install Kubernetes Code Generators from k8s.io/code-generator

VERSION=$(go list -m  k8s.io/api  | cut -d ' ' -f2)
GOBIN="$(go env GOBIN)"
gopath="$(go env GOPATH)"
gobin="${GOBIN:-$(go env GOPATH)/bin}"
go install k8s.io/code-generator/cmd/{deepcopy-gen,client-gen,lister-gen,informer-gen,defaulter-gen,register-gen}@$VERSION

# Generate Code
IFS=','
for API_PKG in $API_PKGS; do
    echo "Generating code for $API_PKG"

    echo "Generating deepcopy funcs"
    GOPATH=$gopath "${gobin}/deepcopy-gen"\
    --output-file "zz_generated.deepcopy.go"\
        --go-header-file "${HDR_FILE}" "${API_PKG}"

    echo "Generating register funcs"
    GOPATH=$gopath "${gobin}/register-gen"\
    --output-file "zz_generated.register.go"\
        --go-header-file "${HDR_FILE}" "${API_PKG}"

    CR_VERSION=${API_PKG#"$CR_PKG/"}

    echo "Generating clientset"
    GOPATH=$gopath "${gobin}/client-gen"\
        --plural-exceptions "Defaults:Defaults"\
        --clientset-name "versioned"\
        --input "${API_PKG}"\
        --input-base "" \
        --output-pkg "${CR_PKG}/generated/${CR_VERSION}/clientset"\
        --go-header-file "${HDR_FILE}"\
        --output-dir "${OUTPUT_DIR}/${CR_VERSION}/clientset" "${API_PKG}"

    echo "Generating listers"
    GOPATH=$gopath "${gobin}/lister-gen"\
        --plural-exceptions "Defaults:Defaults"\
        --output-pkg "${CR_PKG}/generated/${CR_VERSION}/listers"\
        --go-header-file "${HDR_FILE}"\
        --output-dir "${OUTPUT_DIR}/${CR_VERSION}/listers" "${API_PKG}"

    echo "Generating informers"
        GOPATH=$gopath "${gobin}/informer-gen"\
            --plural-exceptions "Defaults:Defaults"\
            --versioned-clientset-package "${CR_PKG}/generated/${CR_VERSION}/clientset/versioned"\
            --listers-package "${CR_PKG}/generated/${CR_VERSION}/listers"\
            --output-pkg "${CR_PKG}/generated/${CR_VERSION}/informers"\
            --go-header-file "${HDR_FILE}"\
            --output-dir "${OUTPUT_DIR}/${CR_VERSION}/informers" "${API_PKG}"
done

CONTROLLER_GEN_VERSION=$(go list -m  sigs.k8s.io/controller-tools  | cut -d ' ' -f2)
go install sigs.k8s.io/controller-tools/cmd/controller-gen@${CONTROLLER_GEN_VERSION}

# # Controller-gen version
echo "Controller-gen: " ${CONTROLLER_GEN_VERSION}
controller-gen crd paths=./crs/api/ingress/v3/...  output:crd:dir=./crs/definition
# remove code-gen annotation (dependabot fails)
if [[ "$OSTYPE" == "darwin"* ]]; then
    find "${CR_DIR}/definition" -type f -name '*.yaml' -exec gsed -i '/controller-gen.kubebuilder.io\/version/d' {} +
else
    find "${CR_DIR}/definition" -type f -name '*.yaml' -exec sed -i '/controller-gen.kubebuilder.io\/version/d' {} +
fi


# # Removal of some fields from the CRDs
# # For example, for now we remove servers from the backend CRD v3
echo "Removing fields from the generated CRDs"
sh crs/remove-fields-from-crds.sh
