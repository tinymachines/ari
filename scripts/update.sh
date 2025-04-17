#!/bin/bash
# ARI - Database Update Script Wrapper
# A simple script to handle database migrations and rebuilds

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Function to display script header
display_header() {
    echo -e "\n${PURPLE}${BOLD}===================================${NC}"
    echo -e "${BLUE}${BOLD}  AWS Resource Inventory - Update  ${NC}"
    echo -e "${PURPLE}${BOLD}===================================${NC}\n"
}

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DEFAULT_DB_PATH="aws_inventory.db"

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is required but not installed.${NC}"
    exit 1
fi

display_header

# Function to show help
show_help() {
    echo -e "${CYAN}Usage:${NC} $0 [options]"
    echo
    echo -e "${CYAN}Options:${NC}"
    echo -e "  --db-path PATH      Path to the database file (default: $DEFAULT_DB_PATH)"
    echo -e "  --rebuild           Completely rebuild the database (will delete all data)"
    echo -e "  --migrate           Migrate the database schema to the latest version"
    echo -e "  --create            Create a new database if it does not exist"
    echo -e "  --clean-backups     Clean up old database backups"
    echo -e "  --keep NUM          Number of backups to keep when cleaning (default: 5)"
    echo -e "  --help              Show this help message"
    echo
    echo -e "${CYAN}Example:${NC}"
    echo -e "  $0 --rebuild                # Completely rebuild the database"
    echo -e "  $0 --migrate --db-path my.db # Migrate a specific database file"
    echo
}

# Process command line arguments
ARGS=()
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --help)
            show_help
            exit 0
            ;;
        --db-path|--rebuild|--migrate|--create|--clean-backups|--keep)
            ARGS+=("$1")
            if [[ "$1" == "--keep" && "$2" =~ ^[0-9]+$ ]]; then
                ARGS+=("$2")
                shift
            elif [[ "$1" == "--db-path" && -n "$2" && ! "$2" =~ ^-- ]]; then
                ARGS+=("$2")
                shift
            fi
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            show_help
            exit 1
            ;;
    esac
    shift
done

# If no arguments, show options
if [ ${#ARGS[@]} -eq 0 ]; then
    echo -e "${YELLOW}Please select an operation to perform:${NC}"
    echo -e "${GREEN}1.${NC} Rebuild database (delete all data & create fresh schema)"
    echo -e "${GREEN}2.${NC} Migrate existing database (update schema while preserving data)"
    echo -e "${GREEN}3.${NC} Create new database (only if it doesn't exist)"
    echo -e "${GREEN}4.${NC} Clean old database backups"
    echo -e "${GREEN}5.${NC} Show help"
    echo -e "${GREEN}0.${NC} Exit"
    
    read -p "$(echo -e ${BOLD}"Enter your choice [0-5]: "${NC})" choice
    
    case $choice in
        1)
            ARGS=("--rebuild")
            ;;
        2)
            ARGS=("--migrate")
            ;;
        3)
            ARGS=("--create")
            ;;
        4)
            ARGS=("--clean-backups")
            ;;
        5)
            show_help
            exit 0
            ;;
        0)
            echo -e "${YELLOW}Exiting...${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice. Exiting.${NC}"
            exit 1
            ;;
    esac
    
    echo
fi

# Display the selected operations
echo -e "${CYAN}Running update script with the following options:${NC} ${ARGS[*]}"

# Check for virtual environment 
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

# Run the Python database update script
python3 "$SCRIPT_DIR/update_db.py" "${ARGS[@]}"
exit_code=$?

if [ $exit_code -ne 0 ]; then
    echo -e "\n${RED}${BOLD}Update failed with exit code: $exit_code${NC}"
    echo -e "${YELLOW}Check the error message above or the log file for details.${NC}"
    exit $exit_code
fi

echo -e "\n${PURPLE}${BOLD}=== ARI Update Complete ===${NC}\n"