"""
menu.py
-------
OPERATION: Terminal Menu (main loop)

Displays the menu, reads the user's choice, and calls the matching
function from the other operation modules. This is the only module
that ties everything together.
"""

from .data_loader import loadfindings
from .ticket_manager import generatetickets
from .views import (
    viewtickets,
    viewcritical,
    viewhigh,
    checkwarnings,
    view_breached,
    showticket,
)
from .actions import assignticket, updatestatus, resolveticket


def print_menu():
    print("=" * 40)
    print(" MEMBER 7 - REMEDIATION & SLA ENGINE")
    print("=" * 40)
    print("1. Load Findings")
    print("2. Generate Remediation Tickets")
    print("3. View All Tickets")
    print("4. View Critical Tickets")
    print("5. View High Priority Tickets")
    print("6. View SLA Warnings")
    print("7. View SLA Breached Tickets")
    print("8. Update Ticket Status")
    print("9. Assign Ticket")
    print("10. Resolve Ticket")
    print("11. Show Ticket Details")
    print("12. Exit")
    print()


def main():
    """Main terminal loop for Member 7."""
    while True:
        print_menu()
        choice = input("Enter your choice: ").strip()
        print()

        if choice == "1":
            loadfindings()
        elif choice == "2":
            generatetickets()
        elif choice == "3":
            viewtickets()
        elif choice == "4":
            viewcritical()
        elif choice == "5":
            viewhigh()
        elif choice == "6":
            checkwarnings()
        elif choice == "7":
            view_breached()
        elif choice == "8":
            updatestatus()
        elif choice == "9":
            assignticket()
        elif choice == "10":
            resolveticket()
        elif choice == "11":
            showticket()
        elif choice == "12":
            print("Exiting Member 7 - Remediation & SLA Engine. Goodbye!\n")
            break
        else:
            print("Invalid choice. Please enter a number from 1 to 12.\n")
