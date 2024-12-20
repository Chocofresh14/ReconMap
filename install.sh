#!/bin/bash

# Script d'installation pour ReconMap

# Vérifier si l'utilisateur a les droits sudo
if ! command -v sudo &> /dev/null; then
    echo "sudo est requis pour l'installation"
    exit 1
fi

# Installer les dépendances nécessaires
echo "Installation des dépendances..."
if command -v apt &> /dev/null; then
    sudo apt update
    sudo apt install -y build-essential
elif command -v yum &> /dev/null; then
    sudo yum groupinstall -y "Development Tools"
fi

# Compiler et installer ReconMap
echo "Compilation et installation de ReconMap..."
make clean
make
make install

echo "Installation terminée !"
echo "Vous pouvez maintenant utiliser ReconMap directement avec la commande : ReconMap"