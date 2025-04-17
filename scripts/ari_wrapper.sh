#!/bin/bash
# ARI - AWS Resource Inventory and Service Mapper
# Bash wrapper script

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is required but not installed.${NC}"
    exit 1
fi

# Function to display script header
display_header() {
    echo -e "\n${PURPLE}${BOLD}=================================${NC}"
    echo -e "${BLUE}${BOLD}  AWS Resource Inventory Tool  ${NC}"
    echo -e "${PURPLE}${BOLD}=================================${NC}\n"
}

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Check if we're in a Python virtual environment
if [[ -z "$VIRTUAL_ENV" ]]; then
    echo -e "${YELLOW}Warning: Not running in a Python virtual environment.${NC}"
    
    # Check if the package is installed
    if ! python3 -c "import ari" &> /dev/null; then
        echo -e "${YELLOW}ARI package not detected. Installing in development mode...${NC}"
        
        # Try to install the package in development mode
        if ! pip install -e "$PROJECT_ROOT" &> /dev/null; then
            echo -e "${RED}Failed to install ARI package. Please run:${NC}"
            echo -e "  ${CYAN}cd $PROJECT_ROOT && pip install -e .${NC}"
            exit 1
        else
            echo -e "${GREEN}ARI package installed successfully.${NC}"
        fi
    fi
fi

display_header

# Run the Python script
echo -e "${CYAN}Loading AWS accounts...${NC}"
python3 "$SCRIPT_DIR/ari_run.py" "$@"

exit_code=$?

if [ $exit_code -ne 0 ]; then
    echo -e "\n${RED}${BOLD}Execution failed with exit code: $exit_code${NC}"
    echo -e "${YELLOW}Check the error message above or the log file for details.${NC}"
else
    if [ -f "aws_inventory.db" ]; then
        echo -e "\n${GREEN}${BOLD}You can now query the database:${NC}"
        echo -e "${CYAN}sqlite3 aws_inventory.db 'SELECT name, resource_count FROM services ORDER BY resource_count DESC LIMIT 10;'${NC}"
    fi
fi

echo -e "\n${PURPLE}${BOLD}=== ARI Execution Complete ===${NC}\n"