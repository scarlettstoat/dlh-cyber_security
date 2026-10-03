#!/bin/bash

mode="$1"

if [ "$mode" = "create" ]; then
    if [ "$#" -ne 3 ]; then
        echo "Usage: $0 create <image_file> <size_mb>"
        exit 1
    fi

    image_file="$2"
    size_mb="$3"
    mapper_name="luks_create_temp"

    echo "Creating ${size_mb}MB encrypted volume..."
    dd if=/dev/zero of="$image_file" bs=1M count="$size_mb"

    sudo cryptsetup luksFormat "$image_file"
    sudo cryptsetup luksOpen "$image_file" "$mapper_name"
    sudo mkfs.ext4 "/dev/mapper/$mapper_name"
    sudo cryptsetup luksClose "$mapper_name"

    echo "Encrypted volume created: $image_file"

elif [ "$mode" = "open" ]; then
    if [ "$#" -ne 4 ]; then
        echo "Usage: $0 open <image_file> <mapper_name> <mount_point>"
        exit 1
    fi

    image_file="$2"
    mapper_name="$3"
    mount_point="$4"

    sudo cryptsetup luksOpen "$image_file" "$mapper_name"
    sudo mkdir -p "$mount_point"
    sudo mount "/dev/mapper/$mapper_name" "$mount_point"

    echo "Volume opened and mounted at: $mount_point"

elif [ "$mode" = "close" ]; then
    if [ "$#" -ne 3 ]; then
        echo "Usage: $0 close <mapper_name> <mount_point>"
        exit 1
    fi

    mapper_name="$2"
    mount_point="$3"

    sudo umount "$mount_point"
    sudo cryptsetup luksClose "$mapper_name"

    echo "Volume unmounted and closed."

else
    echo "Invalid mode. Use create, open or close."
    exit 1
fi
