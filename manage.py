#!/usr/bin/env python
"""
Django's command-line utility for administrative tasks.
Walmart Digital Retailer Pass (DRP) System

This is the main entry point for the Django application.
Use this file to run management commands like:
- python manage.py runserver
- python manage.py migrate
- python manage.py createsuperuser
- python manage.py collectstatic
- python manage.py test

For the Walmart DRP system, you can also run:
- python manage.py shell (to interact with DRP models)
- python manage.py loaddata fixtures/sample_sellers.json (load sample data)
"""
import os
import sys


def main():
    """Run administrative tasks for the Walmart DRP system."""
    # Set the default Django settings module for the DRP project
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'drp_project.settings')
    
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment? \n\n"
            "For the Walmart DRP system, ensure you have installed:\n"
            "- Django>=4.2\n"
            "- djangorestframework\n"
            "- PyJWT\n"
            "- qrcode[pil]\n"
            "- django-cors-headers"
        ) from exc
    
    # Execute the Django management command
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()