output_file="password_hashes.txt"
> $output_file

generate_random_password() {
    openssl rand -base64 12
}

# Get a list of all regular users (UID >= 1000 and valid shell)
get_all_users() {
    awk -F: '($3 >= 1000 && $7 ~ /\/(bash|sh|zsh|ksh|fish)$/) {print $1}' /etc/passwd
}

change_password() {
    local user=$1
    local new_password=$(generate_random_password)
    echo "$user:$new_password" | sudo chpasswd
    local password_hash=$(sudo grep "^$user:" /etc/shadow | cut -d: -f2)
    echo "$user:$password_hash" >> $output_file
}

main() {
    
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root" 
        exit 1
    fi

    local users=$(get_regular_users)

    for user in $users; do
        if id -u $user >/dev/null 2>&1; then
            change_password $user
        fi
    done

    echo "Password hashes recorded in $output_file"
}

main

