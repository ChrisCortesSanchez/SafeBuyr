# Makefile for SafeBuyr E-commerce Security Platform
# Simplifies development, testing, and exploitation workflows

.PHONY: help install install-dev venv setup init-db reset-db backup-db \
        run run-secure run-debug run-background stop \
        docker-build docker-up docker-down docker-logs docker-shell docker-rebuild \
        test test-vuln test-secure test-scanner test-coverage \
        exploit-all exploit-sqli exploit-xss exploit-idor exploit-auth exploit-cmdi exploit-csrf exploit-chain \
        scan scan-secure \
        lint lint-security format format-check quality \
        docs-serve clean clean-all logs ps status \
        dev-setup dev-test demo full-test info credentials urls version

# Default target
.DEFAULT_GOAL := help

# Variables
PYTHON := python3                 # host interpreter, used only to create the venv
VENV := venv
VENV_PY := $(VENV)/bin/python     # venv interpreter, used to run everything else
PIP := $(VENV)/bin/pip
APP_URL := http://localhost:5001  # vulnerable app
SECURE_URL := http://localhost:5002  # hardened app

# Colors for output
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
NC := \033[0m # No Color

##@ General

help: ## Display this help message
	@echo "$(GREEN)SafeBuyr E-commerce - Makefile Commands$(NC)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make $(YELLOW)<target>$(NC)\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  $(GREEN)%-15s$(NC) %s\n", $$1, $$2 } /^##@/ { printf "\n$(YELLOW)%s$(NC)\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Setup & Installation

venv: ## Create virtual environment
	@echo "$(GREEN)Creating virtual environment...$(NC)"
	$(PYTHON) -m venv $(VENV)
	@echo "$(GREEN)Virtual environment created!$(NC)"
	@echo "$(YELLOW)Activate with: source $(VENV)/bin/activate$(NC)"

install: ## Install dependencies into the venv
	@echo "$(GREEN)Installing dependencies...$(NC)"
	$(PIP) install -r requirements.txt
	@echo "$(GREEN)Dependencies installed successfully!$(NC)"

install-dev: ## Install development dependencies into the venv
	@echo "$(GREEN)Installing development dependencies...$(NC)"
	$(PIP) install -r requirements.txt
	$(PIP) install pytest pytest-cov black flake8 pylint bandit
	@echo "$(GREEN)Development dependencies installed!$(NC)"

setup: venv install init-db ## Complete initial setup (venv + deps + databases)
	@echo "$(GREEN)Setup complete! Run 'make run' to start the application.$(NC)"

##@ Database

init-db: ## Seed both databases with sample data
	@echo "$(GREEN)Initializing databases...$(NC)"
	$(VENV_PY) -m app.data.seed_data
	$(VENV_PY) -m app.secured.data.seed_data_secure
	@echo "$(GREEN)Databases initialized with sample data!$(NC)"

reset-db: ## Reset both databases to initial state
	@echo "$(YELLOW)Resetting databases...$(NC)"
	rm -f app/data/ecommerce.db app/secured/data/ecommerce_secure.db
	$(MAKE) init-db
	@echo "$(GREEN)Database reset complete!$(NC)"

backup-db: ## Backup current vulnerable database
	@echo "$(GREEN)Backing up database...$(NC)"
	cp app/data/ecommerce.db app/data/ecommerce_backup_$(shell date +%Y%m%d_%H%M%S).db
	@echo "$(GREEN)Database backed up!$(NC)"

##@ Running

run: ## Run the vulnerable application (port 5001)
	@echo "$(GREEN)Starting SafeBuyr (Vulnerable Mode)...$(NC)"
	@echo "$(YELLOW)Access at: $(APP_URL)$(NC)"
	$(VENV_PY) -m app.app

run-secure: ## Run the hardened application (port 5002)
	@echo "$(GREEN)Starting SafeBuyr (Secure Mode)...$(NC)"
	@echo "$(YELLOW)Access at: $(SECURE_URL)$(NC)"
	$(VENV_PY) -m app.secured.app_secure

run-debug: ## Run the vulnerable app (debug is already enabled)
	@echo "$(GREEN)Starting in DEBUG mode...$(NC)"
	$(VENV_PY) -m app.app

run-background: ## Run both apps in the background (logs to vulnerable.log / secure.log)
	@echo "$(GREEN)Starting both apps in background...$(NC)"
	@nohup $(VENV_PY) -m app.app > vulnerable.log 2>&1 &
	@nohup $(VENV_PY) -m app.secured.app_secure > secure.log 2>&1 &
	@sleep 3
	@echo "$(GREEN)Vulnerable: $(APP_URL)  |  Secure: $(SECURE_URL)$(NC)"

stop: ## Stop both background apps
	@echo "$(RED)Stopping applications...$(NC)"
	@pkill -f "app.secured.app_secure" 2>/dev/null || true
	@pkill -f "app\.app" 2>/dev/null || true
	@echo "$(GREEN)Stopped (if they were running).$(NC)"

##@ Docker

docker-build: ## Build Docker images
	@echo "$(GREEN)Building Docker images...$(NC)"
	docker-compose build
	@echo "$(GREEN)Docker images built!$(NC)"

docker-up: ## Start application in Docker
	@echo "$(GREEN)Starting Docker containers...$(NC)"
	docker-compose up -d
	@echo "$(GREEN)Vulnerable: $(APP_URL)  |  Secure: $(SECURE_URL)$(NC)"

docker-down: ## Stop Docker containers
	@echo "$(RED)Stopping Docker containers...$(NC)"
	docker-compose down

docker-logs: ## View Docker logs
	docker-compose logs -f

docker-shell: ## Open shell in Docker container
	docker-compose exec web /bin/bash

docker-rebuild: docker-down docker-build docker-up ## Rebuild and restart Docker

##@ Testing

test: ## Run all regression tests (requires both apps running: make run-background)
	@echo "$(GREEN)Running all tests...$(NC)"
	@echo "$(YELLOW)Note: both apps must be running (make run-background).$(NC)"
	$(VENV_PY) -m pytest tests/ -v

test-vuln: ## Run vulnerable-app regression tests
	@echo "$(GREEN)Testing vulnerable version...$(NC)"
	$(VENV_PY) -m pytest tests/test_vulnerable_regress.py -v

test-secure: ## Run hardened-app regression tests
	@echo "$(GREEN)Testing secure version...$(NC)"
	$(VENV_PY) -m pytest tests/test_secure_regress.py -v

test-scanner: ## Run scanner regression tests
	@echo "$(GREEN)Testing scanner...$(NC)"
	$(VENV_PY) -m pytest tests/test_scanner_regress.py -v

test-coverage: ## Run tests with coverage report
	@echo "$(GREEN)Running tests with coverage...$(NC)"
	$(VENV_PY) -m pytest tests/ --cov=app --cov-report=html --cov-report=term
	@echo "$(GREEN)Coverage report generated in htmlcov/$(NC)"

##@ Exploitation (target the vulnerable app)

exploit-all: ## Run all exploit scripts sequentially
	@echo "$(GREEN)Running all exploits...$(NC)"
	@for exploit in exploits/*.py; do \
		echo "$(YELLOW)Running $$exploit...$(NC)"; \
		$(VENV_PY) $$exploit $(APP_URL); \
		echo ""; \
	done

exploit-sqli: ## Run SQL injection exploit
	$(VENV_PY) exploits/sqli.py $(APP_URL)

exploit-xss: ## Run XSS exploit
	$(VENV_PY) exploits/xss.py $(APP_URL)

exploit-idor: ## Run IDOR exploit
	$(VENV_PY) exploits/idor.py $(APP_URL)

exploit-auth: ## Run authentication bypass exploit
	$(VENV_PY) exploits/auth_bypass.py $(APP_URL)

exploit-cmdi: ## Run command injection exploit
	$(VENV_PY) exploits/cmndi.py $(APP_URL)

exploit-csrf: ## Run CSRF exploit
	$(VENV_PY) exploits/csrf.py $(APP_URL)

exploit-chain: ## Run full automated attack chain
	$(VENV_PY) exploits/all_in_one.py $(APP_URL)

##@ Scanning

scan: ## Scan the vulnerable app (report written to docs/)
	@echo "$(GREEN)Running vulnerability scanner against $(APP_URL)...$(NC)"
	$(VENV_PY) scanner/vulnerability_scanner.py $(APP_URL)
	@echo "$(GREEN)Scan complete! Open the newest docs/security_report_*.html$(NC)"

scan-secure: ## Scan the hardened app (report written to docs/)
	@echo "$(GREEN)Running vulnerability scanner against $(SECURE_URL)...$(NC)"
	$(VENV_PY) scanner/vulnerability_scanner.py $(SECURE_URL)
	@echo "$(GREEN)Scan complete! Open the newest docs/security_report_*.html$(NC)"

##@ Code Quality

lint: ## Run linting
	@echo "$(GREEN)Running linting...$(NC)"
	$(VENV_PY) -m flake8 app/ exploits/ scanner/ tests/ --max-line-length=100

lint-security: ## Run security linting
	@echo "$(GREEN)Running security analysis...$(NC)"
	$(VENV_PY) -m bandit -r app/ -ll

format: ## Format code with black
	@echo "$(GREEN)Formatting code...$(NC)"
	$(VENV_PY) -m black app/ exploits/ scanner/ tests/

format-check: ## Check code formatting
	@echo "$(GREEN)Checking code formatting...$(NC)"
	$(VENV_PY) -m black app/ exploits/ scanner/ tests/ --check

quality: lint lint-security format-check ## Run all quality checks

##@ Documentation

docs-serve: ## Serve the docs/ folder (reports) locally
	@echo "$(GREEN)Serving docs at http://localhost:8000$(NC)"
	cd docs && $(VENV_PY) -m http.server 8000

##@ Utility

clean: ## Clean up generated files
	@echo "$(RED)Cleaning up...$(NC)"
	find . -type f -name '*.pyc' -delete
	find . -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name '*.egg-info' -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache htmlcov .coverage dist build
	@echo "$(GREEN)Cleanup complete!$(NC)"

clean-all: clean ## Deep clean including databases, backups, logs and reports
	@echo "$(RED)Deep cleaning...$(NC)"
	rm -f app/data/ecommerce_backup_*.db
	rm -f vulnerable.log secure.log app.log
	rm -f docs/security_report_*.html docs/security_report_*.txt
	@echo "$(GREEN)Deep cleanup complete!$(NC)"

logs: ## Tail the vulnerable app log
	@tail -f vulnerable.log 2>/dev/null || echo "No log file found (start with: make run-background)"

ps: ## Show running app processes
	@echo "$(GREEN)SafeBuyr processes:$(NC)"
	@pgrep -fl "app.app|app.secured.app_secure" || echo "No app processes running"

status: ## Check both apps' status
	@echo "$(GREEN)Checking application status...$(NC)"
	@curl -s -o /dev/null -w "Vulnerable ($(APP_URL)): %{http_code}\n" $(APP_URL) || echo "$(RED)Vulnerable app not running$(NC)"
	@curl -s -o /dev/null -w "Secure     ($(SECURE_URL)): %{http_code}\n" $(SECURE_URL) || echo "$(RED)Secure app not running$(NC)"

##@ Development Workflow

dev-setup: setup install-dev ## Complete development setup
	@echo "$(GREEN)Development environment ready!$(NC)"

dev-test: format lint test ## Format, lint, and test
	@echo "$(GREEN)All checks passed!$(NC)"

demo: run ## Start the vulnerable app for demonstration
	@echo "$(YELLOW)Default credentials: admin/admin123, user/password$(NC)"

full-test: reset-db run-background test scan stop ## Reset, start both apps, test, scan, stop
	@echo "$(GREEN)Full test suite complete!$(NC)"

##@ Information

info: ## Show project information
	@echo "$(GREEN)SafeBuyr E-commerce - Project Information$(NC)"
	@echo ""
	@echo "$(YELLOW)Vulnerable URL:$(NC) $(APP_URL)"
	@echo "$(YELLOW)Secure URL:$(NC)     $(SECURE_URL)"
	@echo "$(YELLOW)Python:$(NC)         $$($(VENV_PY) --version 2>/dev/null || echo 'venv not created - run: make venv')"
	@echo "$(YELLOW)Databases:$(NC)      app/data/ecommerce.db, app/secured/data/ecommerce_secure.db"
	@echo ""
	@echo "$(YELLOW)Default Credentials:$(NC)"
	@echo "  Admin: admin / admin123"
	@echo "  User:  user / password"
	@echo ""
	@echo "$(YELLOW)Vulnerabilities demonstrated:$(NC)"
	@echo "  1. SQL Injection (product search, login)"
	@echo "  2. Stored XSS (product reviews)"
	@echo "  3. IDOR (orders, cart)"
	@echo "  4. Weak password hashing (MD5)"
	@echo "  5. Missing CSRF protection"
	@echo "  6. Missing security headers"

credentials: ## Show default credentials
	@echo "$(YELLOW)Default Credentials:$(NC)"
	@echo "  Admin: admin / admin123"
	@echo "  User:  user / password"

urls: ## Show important URLs (vulnerable app)
	@echo "$(YELLOW)Important URLs:$(NC)"
	@echo "  Homepage:    $(APP_URL)/"
	@echo "  Products:    $(APP_URL)/products"
	@echo "  Login:       $(APP_URL)/login"
	@echo "  Register:    $(APP_URL)/register"
	@echo "  Cart:        $(APP_URL)/cart"
	@echo "  Orders:      $(APP_URL)/orders"
	@echo "  Admin Panel: $(APP_URL)/admin"

version: ## Show version information
	@echo "SafeBuyr E-commerce v1.0.0"
	@$(VENV_PY) --version 2>/dev/null || echo "venv not created - run: make venv"
