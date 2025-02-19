docker run -v "$(pwd):/mnt" -it sagemath/sagemath:8.9  "cd /mnt && sage $1"
