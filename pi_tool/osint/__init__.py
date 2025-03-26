"""
OSINT (Open Source Intelligence) module for the Ultimate PI Tool.

This module provides functionality for gathering intelligence from various
open sources including social media, email lookups, domain information,
and data breach checks.
"""

from .linkedin import LinkedInOSINT
from .twitter import TwitterOSINT
from .email import EmailOSINT
from .domain import DomainOSINT
from .username import UsernameOSINT
from .breaches import BreachOSINT

def handle_osint_command(args):
    """Handle OSINT command line arguments and dispatch to appropriate handler."""
    if args.osint_command == "linkedin":
        linkedin = LinkedInOSINT()
        if args.username:
            linkedin.get_profile(args.username)
        elif args.search:
            linkedin.search_people(args.search)
        else:
            print("Please provide a LinkedIn username or search term.")
    
    elif args.osint_command == "twitter":
        twitter = TwitterOSINT()
        if args.username:
            twitter.get_profile(args.username)
        elif args.search:
            twitter.search_tweets(args.search, args.count)
        else:
            print("Please provide a Twitter username or search term.")
    
    elif args.osint_command == "email":
        email = EmailOSINT()
        if args.address:
            email.lookup(args.address)
        else:
            print("Please provide an email address.")
    
    elif args.osint_command == "domain":
        domain = DomainOSINT()
        if args.name:
            domain.lookup(args.name)
        else:
            print("Please provide a domain name.")
    
    else:
        print(f"Unknown OSINT command: {args.osint_command}")
