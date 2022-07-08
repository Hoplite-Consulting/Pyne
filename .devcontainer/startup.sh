#!/bin/bash

echo "Running Startup Script"

# Install Python Requirements
pipreqs --force
pip3 install -r requirements.txt
rm requirements.txt

echo "Startup Script Complete"