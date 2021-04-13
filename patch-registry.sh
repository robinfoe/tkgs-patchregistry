#!/bin/bash


usage()
{
    echo "Usage: [FILE]... [Interactive] 

Mandatory arguments 
        -c, --tkg_cluster_name            guest_cluster_name
        -n, --tkg_cluster_namespace       guest_cluster_namespace
        -r, --url_registry
        -t, --registry_certificate_path    
        --registry_credential_encoded
        --vc_root_password
        --vc_admin_passowrd
        --vc_admin_user
        --vc_ip
        --sv_ip
        -h, --help                        show help.
        
        Example:
        ./tkg-insecure-registry.sh -c \${cluster_name} -n \${namespace} -r \${url_registry} --vc_admin_passowrd \${admin_pass} --vc_admin_user \${admin_user} --vc_ip \${vc_ip} --sv_ip \${supervisor_cliuster_ip} --vc_root_password \${root_pass}"
}

SV_IP=''  #'192.168.40.129' #VIP for the Supervisor Cluster
VC_IP='' #URL for the vCenter
VC_ADMIN_USER='' #'administrator@vsphere.local' #User for the Supervisor Cluster
VC_ADMIN_PASSWORD="" #'VMware1!' #Password for the Supervisor Cluster user
VC_ROOT_PASSWORD=""
TKG_CLUSTER_NAME="" # Name of the TKG cluster
TKG_CLUSTER_NAMESPACE="" # Namespace where the TKG cluster is deployed
REGISTRY_CREDENTIAL_ENCODED=""
URL_REGISTRY="" # URL of the Registry to be added 
WORKSPACE=`pwd`


# Check if parameter value is empty.
check_if_value_exist()
{
    current_param=$1
    if [ "$current_param" = "" ]
        then 
        echo "parameter cannot be empty"
        exit 1
    fi
}


check_if_any_argument_supplied()
{
    if [ "$#" -eq 0 ]
        then
        usage
        exit 1
    fi
}

print_current_arg()
{
      echo "Debug $1: $2"
}

define_arguments()
{
    check_if_any_argument_supplied $@   

    while [ "$#" -gt 0 ]; do
    # while [ "x$1" != "x" ]; do
    # while [ "$1" != "" ]; do
        case $1 in
            -c | --tkg_cluster_name ) shift
                check_if_value_exist $1
                TKG_CLUSTER_NAME=$1
                print_current_arg "TKG_CLUSTER_NAME" $1
                ;;
            -n | --tkg_cluster_namespace ) shift 
                check_if_value_exist $1 
                TKG_CLUSTER_NAMESPACE=$1
                print_current_arg "TKG_CLUSTER_NAMESPACE" $1
                ;;
            -r | --url_registry ) shift 
                check_if_value_exist $1 
                URL_REGISTRY=$1
                print_current_arg "URL_REGISTRY" $1
                ;;
            -t | --registry_certificate_path ) shift 
                check_if_value_exist $1 
                REGISTRY_CERTIFICATE_PATH=$1
                print_current_arg "REGISTRY_CERTIFICATE_PATH" $1
                ;;
            --vc_admin_passowrd ) shift 
                check_if_value_exist $1 
                VC_ADMIN_PASSWORD=$1
                ;;
            --vc_root_password ) shift 
                check_if_value_exist $1 
                VC_ROOT_PASSWORD=$1
                ;;
            --vc_admin_user ) shift 
                check_if_value_exist $1 
                VC_ADMIN_USER=$1
                print_current_arg "VC_ADMIN_USER" $1
                ;;
            --vc_ip ) shift 
                check_if_value_exist $1 
                VC_IP=$1
                print_current_arg "VC_IP" $1
                ;;
            --sv_ip ) shift 
                check_if_value_exist $1 
                SV_IP=$1
                print_current_arg "SV_IP" $1
                ;;
            --registry_credential_encoded ) shift 
                check_if_value_exist $1 
                REGISTRY_CREDENTIAL_ENCODED=$1
                print_current_arg "SV_IP" $1
                ;;
            -h | --help )        
                usage
                exit
                ;;
            * ) 
                usage
                exit 1
                ;;
        esac
        shift
    done

#     check_if_argument_exist
}

define_arguments $@


URL_REGISTRY_TRIM=$(echo "${URL_REGISTRY}" | sed 's~http[s]*://~~g') # Sanitize registry URL to remove http/https

# Logging function that will redirect to stderr with timestamp:
logerr() { echo "$(date) ERROR: $@" 1>&2; }
# Logging function that will redirect to stdout with timestamp
loginfo() { echo "$(date) INFO: $@" ;}

# Verify if required arguments are met

if [[ -z "$1" || -z "$2" || -z "$3" ]]
  then
    logerr "Invalid arguments. Exiting..."
    exit 2
fi

# Exit the script if the supervisor cluster is not up
if [ $(curl -m 15 -k -s -o /dev/null -w "%{http_code}" https://"${SV_IP}") -ne "200" ]; then
    logerr "Supervisor cluster not ready. Exiting..."
    exit 2
fi

# If the supervisor cluster is ready, get the token for TKG cluster
loginfo "Supervisor cluster is ready!"
loginfo "Getting TKC Kubernetes API token..."

# Get the TKG Kubernetes API token by login into the Supervisor Cluster
TKC_API=$(curl -XPOST -s -u "${VC_ADMIN_USER}":"${VC_ADMIN_PASSWORD}" https://"${SV_IP}":443/wcp/login -k -d '{"guest_cluster_name":"'"${TKG_CLUSTER_NAME}"'", "guest_cluster_namespace":"'"${TKG_CLUSTER_NAMESPACE}"'"}' -H "Content-Type: application/json" | jq -r '.guest_cluster_server')
TOKEN=$(curl -XPOST -s -u "${VC_ADMIN_USER}":"${VC_ADMIN_PASSWORD}" https://"${SV_IP}":443/wcp/login -k -d '{"guest_cluster_name":"'"${TKG_CLUSTER_NAME}"'", "guest_cluster_namespace":"'"${TKG_CLUSTER_NAMESPACE}"'"}' -H "Content-Type: application/json" | jq -r '.session_id')
# I'm sure there is a better way to store the JSON in two variables in a single pipe execution. But I can't be bothered to search on StackOverflow right now.

# Verify if the token is valid
if [ $(curl -k -s -o /dev/null -w "%{http_code}" https://"${TKC_API}":6443/ --header "Authorization: Bearer "${TOKEN}"") -ne "200" ]
then
      logerr "TKC Kubernetes API token is not valid. Exiting..."
      exit 2
else
      loginfo "TKC Kubernetes API token is valid!"
fi

## create working folder 

WORKSPACE=$WORKSPACE/$TKG_CLUSTER_NAMESPACE/$TKG_CLUSTER_NAME
mkdir -p $WORKSPACE


#Get the list of nodes in the cluster
curl -XGET -k --fail -s https://"${TKC_API}":6443/api/v1/nodes --header 'Content-Type: application/json' --header "Authorization: Bearer "${TOKEN}"" >> /dev/null
if [ $? -eq 0 ] ;
then      
      loginfo "Getting the IPs of the nodes in the cluster..."
      curl -XGET -k --fail -s https://"${TKC_API}":6443/api/v1/nodes --header 'Content-Type: application/json' --header "Authorization: Bearer "${TOKEN}"" | jq -r '.items[].status.addresses[] | select(.type=="InternalIP").address' > $WORKSPACE/ip-nodes-tkg
      loginfo "The nodes IPs are: "$(column $WORKSPACE/ip-nodes-tkg | sed 's/\t/,/g')""
else
      logerr "There was an error processing the IPs of the nodes. Exiting..."
      exit 2
fi


#SSH into vCenter to get credentials for the supervisor cluster master VMs
sshpass -p "${VC_ROOT_PASSWORD}" ssh -t -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no -q root@"${VC_IP}" com.vmware.shell /usr/lib/vmware-wcp/decryptK8Pwd.py > $WORKSPACE/sv-cluster-creds 2>&1
if [ $? -eq 0 ] ;
then      
      loginfo "Connecting to the vCenter to get the supervisor cluster VM credentials..."
      SV_MASTER_IP=$(cat $WORKSPACE/sv-cluster-creds | sed -n -e 's/^.*IP: //p')
      SV_MASTER_PASSWORD=$(cat $WORKSPACE/sv-cluster-creds | sed -n -e 's/^.*PWD: //p')

      SV_MASTER_IP="$(echo -e "${SV_MASTER_IP}" | tr -d '[:space:]')"
      loginfo "Supervisor cluster master IP is: "${SV_MASTER_IP}"--"
else
      logerr "There was an error logging into the vCenter. Exiting..."
      exit 2
fi

#Get Supervisor Cluster token to get the TKC nodes SSH Password
loginfo "Getting Supervisor Cluster Kubernetes API token..."
SV_TOKEN=$(curl -XPOST -s --fail -u "${VC_ADMIN_USER}":"${VC_ADMIN_PASSWORD}" https://"${SV_IP}":443/wcp/login -k -H "Content-Type: application/json" | jq -r '.session_id')

# Verify if the Supervisor Cluster token is valid
# Health check in /api/v1 (Supervisor Cluster forbids accessing / directly (TKC cluster allows it))
if [ $(curl -k -s -o /dev/null -w "%{http_code}" https://"${SV_IP}":6443/api/v1 --header "Authorization: Bearer "${SV_TOKEN}"") -ne "200" ]
then
      logerr "Supervisor Cluster Kubernetes API token is not valid. Exiting..."
      exit 2
else
      loginfo "Supervisor Cluster Kubernetes API token is valid!"
fi

# Get the TKC nodes SSH private key from the Supervisor Cluster
curl -XGET -k --fail -s https://"${SV_IP}":6443/api/v1/namespaces/"${TKG_CLUSTER_NAMESPACE}"/secrets/"${TKG_CLUSTER_NAME}"-ssh --header 'Content-Type: application/json' --header "Authorization: Bearer "${SV_TOKEN}"" >> /dev/null 
if [ $? -eq 0 ] ;
then      
      loginfo "Getting the TKC nodes SSH private key from the supervisor cluster..."
      curl -XGET -k --fail -s https://"${SV_IP}":6443/api/v1/namespaces/"${TKG_CLUSTER_NAMESPACE}"/secrets/"${TKG_CLUSTER_NAME}"-ssh --header 'Content-Type: application/json' --header "Authorization: Bearer "${SV_TOKEN}"" | jq -r '.data."ssh-privatekey"' | base64 -d > $WORKSPACE/tkc-ssh-privatekey
      #Set correct permissions for TKC SSH private key
      chmod 600 $WORKSPACE/tkc-ssh-privatekey
      loginfo "TKC SSH private key retrieved successfully!"
else
      logerr "There was an error getting the TKC nodes SSH private key. Exiting..."
      exit 2
fi

# Get the TKC nodes SSH password from the Supervisor Cluster
curl -XGET -k --fail -s https://"${SV_IP}":6443/api/v1/namespaces/"${TKG_CLUSTER_NAMESPACE}"/secrets/"${TKG_CLUSTER_NAME}"-ssh-password --header 'Content-Type: application/json' --header "Authorization: Bearer "${SV_TOKEN}"" >> /dev/null 
if [ $? -eq 0 ] ;
then      
      loginfo "Getting the TKC nodes SSH private key from the supervisor cluster..."
      curl -XGET -k --fail -s https://"${SV_IP}":6443/api/v1/namespaces/"${TKG_CLUSTER_NAMESPACE}"/secrets/"${TKG_CLUSTER_NAME}"-ssh-password --header 'Content-Type: application/json' --header "Authorization: Bearer "${SV_TOKEN}"" | jq -r '.data."ssh-passwordkey"' | base64 -d > $WORKSPACE/tkc-ssh-password
      loginfo "TKC SSH private key retrieved successfully!"
      TKC_PASS=$(cat $WORKSPACE/tkc-ssh-password)
else
      logerr "There was an error getting the TKC nodes SSH private key. Exiting..."
      exit 2
fi


# Create workspace folder in supervisor cluster master vm 
loginfo "Create workspace folder in supervisor master"

sshpass -p "${SV_MASTER_PASSWORD}" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null  root@"${SV_MASTER_IP}" "mkdir -p ~/$TKG_CLUSTER_NAMESPACE/$TKG_CLUSTER_NAME"

sshpass -p "${SV_MASTER_PASSWORD}" scp -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $WORKSPACE/tkc-ssh-privatekey root@"${SV_MASTER_IP}":./$TKG_CLUSTER_NAMESPACE/$TKG_CLUSTER_NAME/tkc-ssh-privatekey >> /dev/null
if [ $? -eq 0 ] ;
then      
      loginfo "TKC SSH private key transferred successfully!"
else
      logerr "There was an error transferring the TKC nodes SSH private key. Exiting..."
      exit 2
fi

# ## Transfer harbor registry certificate to tkc 
sshpass -p "${SV_MASTER_PASSWORD}" scp -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $REGISTRY_CERTIFICATE_PATH root@"${SV_MASTER_IP}":./$TKG_CLUSTER_NAMESPACE/$TKG_CLUSTER_NAME/harbor-ca.crt >> /dev/null

export SSHPASS="${SV_MASTER_PASSWORD}"

# ## apply harbor CA to all the nodes 
while IFS= read -r IPS_NODES_READ; do

## copy registry certificate to tkc 
loginfo "Copy Registry Certificate $IPS_NODES_READ"
sshpass -p "${SV_MASTER_PASSWORD}"  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -q -t root@"${SV_MASTER_IP}" scp -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ./$TKG_CLUSTER_NAMESPACE/$TKG_CLUSTER_NAME/tkc-ssh-privatekey ./$TKG_CLUSTER_NAMESPACE/$TKG_CLUSTER_NAME/harbor-ca.crt vmware-system-user@"${IPS_NODES_READ}":./harbor-ca.crt < /dev/null

loginfo "Add Registry certificate $IPS_NODES_READ"
sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -q -t root@"${SV_MASTER_IP}" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ./$TKG_CLUSTER_NAMESPACE/$TKG_CLUSTER_NAME/tkc-ssh-privatekey -t -q vmware-system-user@"${IPS_NODES_READ}" << EOF
		echo $TKC_PASS | sudo -S -k bash -c "cat /home/vmware-system-user/harbor-ca.crt >> /etc/pki/tls/certs/ca-bundle.crt"
EOF


sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -q -t root@"${SV_MASTER_IP}" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ./$TKG_CLUSTER_NAMESPACE/$TKG_CLUSTER_NAME/tkc-ssh-privatekey -t -q vmware-system-user@"${IPS_NODES_READ}" << EOF
		echo $TKC_PASS | sudo -S -k bash -c "sed '/\[plugins.cri.registry\]/a \      [plugins.cri.registry.configs]\n        [plugins.cri.registry.configs.\"${URL_REGISTRY}\".auth]\n          auth=\"${REGISTRY_CREDENTIAL_ENCODED}\"'  /etc/containerd/config.toml > config.gen.toml" 
EOF

sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -q -t root@"${SV_MASTER_IP}" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ./$TKG_CLUSTER_NAMESPACE/$TKG_CLUSTER_NAME/tkc-ssh-privatekey -t -q vmware-system-user@"${IPS_NODES_READ}" << EOF
		echo $TKC_PASS | sudo -S -k bash -c "mv config.gen.toml /etc/containerd/config.toml" 
EOF

sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -q -t root@"${SV_MASTER_IP}" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ./$TKG_CLUSTER_NAMESPACE/$TKG_CLUSTER_NAME/tkc-ssh-privatekey -t -q vmware-system-user@"${IPS_NODES_READ}" << EOF
		echo $TKC_PASS | sudo -S -k bash -c "systemctl restart containerd" 
EOF


done < "$WORKSPACE/ip-nodes-tkg"



