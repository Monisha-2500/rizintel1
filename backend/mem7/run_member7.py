"""
====================================================================
 MEMBER 7 - REMEDIATION, TICKETING & SLA AUTOMATION ENGINE
====================================================================
Entry point script.

This file just starts the terminal menu. All the actual operations
(loading data, SLA rules, ticket creation, views, status changes,
saving output) are split into separate files inside member7_app/.

Run with:
    python run_member7.py
====================================================================
"""

from member7_app.menu import main

if __name__ == "__main__":
    main()
