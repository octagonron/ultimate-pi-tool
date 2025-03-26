"""
Twitter OSINT module for the Ultimate PI Tool.

This module provides functionality for gathering intelligence from Twitter
using the Twitter API.
"""

import os
import sys
import json
from rich.console import Console
from rich.table import Table

# Add path for data API access
sys.path.append('/opt/.manus/.sandbox-runtime')
from data_api import ApiClient

console = Console()

class TwitterOSINT:
    """Twitter OSINT class for gathering intelligence from Twitter."""
    
    def __init__(self):
        """Initialize the Twitter OSINT module."""
        self.client = ApiClient()
        
    def get_profile(self, username):
        """Get Twitter profile information for a given username."""
        console.print(f"[bold blue]Fetching Twitter profile for[/] [bold green]{username}[/]")
        
        try:
            # Use the Twitter API to get profile data
            result = self.client.call_api('Twitter/get_user_profile_by_username', 
                                         query={'username': username})
            
            # Save the raw data to a file
            with open(f"/home/ubuntu/pi_tool/twitter_{username}_raw.json", "w") as f:
                json.dump(result, f, indent=4)
            
            # Display the profile information
            profile_data = self._extract_profile_data(result)
            
            # Create a table for display
            table = Table(title=f"Twitter Profile: {username}")
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="green")
            
            for field, value in profile_data.items():
                table.add_row(field, str(value))
            
            console.print(table)
            
            console.print(f"[bold green]Success![/] Full profile data saved to [bold]twitter_{username}_raw.json[/]")
            return profile_data
                
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return None
    
    def search_tweets(self, query, count=20, cursor=None):
        """Search for tweets on Twitter based on query."""
        console.print(f"[bold blue]Searching Twitter for tweets matching:[/] [bold green]{query}[/]")
        
        try:
            # Use the Twitter API to search for tweets
            params = {
                'query': query,
                'count': count,
                'type': 'Top'
            }
            
            if cursor:
                params['cursor'] = cursor
                
            result = self.client.call_api('Twitter/search_twitter', query=params)
            
            # Save the raw data to a file
            filename = f"/home/ubuntu/pi_tool/twitter_search_{query.replace(' ', '_')}_raw.json"
            with open(filename, "w") as f:
                json.dump(result, f, indent=4)
            
            # Extract and display the tweets
            tweets = self._extract_tweets(result)
            
            # Create a table for display
            table = Table(title=f"Twitter Search Results: {query}")
            table.add_column("Author", style="cyan")
            table.add_column("Tweet", style="green")
            table.add_column("Stats", style="yellow")
            
            for tweet in tweets:
                table.add_row(
                    tweet.get('author', 'N/A'),
                    tweet.get('text', 'N/A')[:100] + ('...' if len(tweet.get('text', '')) > 100 else ''),
                    f"Likes: {tweet.get('likes', 0)}, Retweets: {tweet.get('retweets', 0)}"
                )
            
            console.print(table)
            
            # Display pagination information
            if 'cursor' in result and ('top' in result['cursor'] or 'bottom' in result['cursor']):
                console.print("[bold blue]Pagination cursors:[/]")
                if 'top' in result['cursor']:
                    console.print(f"Top cursor: {result['cursor']['top']}")
                if 'bottom' in result['cursor']:
                    console.print(f"Bottom cursor: {result['cursor']['bottom']}")
            
            console.print(f"[bold green]Success![/] Full search results saved to [bold]{filename}[/]")
            return tweets
                
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return None
    
    def get_user_tweets(self, user_id, count=20, cursor=None):
        """Get tweets from a specific user by their ID."""
        console.print(f"[bold blue]Fetching tweets for user ID:[/] [bold green]{user_id}[/]")
        
        try:
            # Use the Twitter API to get user tweets
            params = {
                'user': user_id,
                'count': count
            }
            
            if cursor:
                params['cursor'] = cursor
                
            result = self.client.call_api('Twitter/get_user_tweets', query=params)
            
            # Save the raw data to a file
            filename = f"/home/ubuntu/pi_tool/twitter_user_tweets_{user_id}_raw.json"
            with open(filename, "w") as f:
                json.dump(result, f, indent=4)
            
            # Extract and display the tweets
            tweets = self._extract_user_tweets(result)
            
            # Create a table for display
            table = Table(title=f"Tweets from User ID: {user_id}")
            table.add_column("Tweet", style="green")
            table.add_column("Stats", style="yellow")
            table.add_column("Date", style="cyan")
            
            for tweet in tweets:
                table.add_row(
                    tweet.get('text', 'N/A')[:100] + ('...' if len(tweet.get('text', '')) > 100 else ''),
                    f"Likes: {tweet.get('likes', 0)}, Retweets: {tweet.get('retweets', 0)}",
                    tweet.get('date', 'N/A')
                )
            
            console.print(table)
            
            # Display pagination information
            if 'cursor' in result and ('top' in result['cursor'] or 'bottom' in result['cursor']):
                console.print("[bold blue]Pagination cursors:[/]")
                if 'top' in result['cursor']:
                    console.print(f"Top cursor: {result['cursor']['top']}")
                if 'bottom' in result['cursor']:
                    console.print(f"Bottom cursor: {result['cursor']['bottom']}")
            
            console.print(f"[bold green]Success![/] Full tweet data saved to [bold]{filename}[/]")
            return tweets
                
        except Exception as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            return None
    
    def _extract_profile_data(self, result):
        """Extract relevant profile data from the API response."""
        profile_data = {}
        
        try:
            # Navigate through the nested structure to get to the user data
            user_data = result.get('result', {}).get('data', {}).get('user', {}).get('result', {})
            
            if user_data:
                # Extract basic information
                profile_data['ID'] = user_data.get('id', 'N/A')
                profile_data['Rest ID'] = user_data.get('rest_id', 'N/A')
                
                # Extract legacy information
                legacy = user_data.get('legacy', {})
                if legacy:
                    profile_data['Name'] = legacy.get('name', 'N/A')
                    profile_data['Screen Name'] = legacy.get('screen_name', 'N/A')
                    profile_data['Description'] = legacy.get('description', 'N/A')
                    profile_data['Location'] = legacy.get('location', 'N/A')
                    profile_data['URL'] = legacy.get('url', 'N/A')
                    profile_data['Followers'] = legacy.get('followers_count', 0)
                    profile_data['Following'] = legacy.get('friends_count', 0)
                    profile_data['Tweets'] = legacy.get('statuses_count', 0)
                    profile_data['Likes'] = legacy.get('favourites_count', 0)
                    profile_data['Listed'] = legacy.get('listed_count', 0)
                    profile_data['Created At'] = legacy.get('created_at', 'N/A')
                    profile_data['Verified'] = legacy.get('verified', False)
                
                # Extract verification information
                verification = user_data.get('verification_info', {})
                if verification:
                    profile_data['Identity Verified'] = verification.get('is_identity_verified', False)
                    
                # Extract professional information
                professional = user_data.get('professional', {})
                if professional:
                    profile_data['Professional Type'] = professional.get('professional_type', 'N/A')
                    
                    # Extract categories
                    categories = professional.get('category', [])
                    if categories:
                        category_names = [cat.get('name', 'N/A') for cat in categories]
                        profile_data['Categories'] = ', '.join(category_names)
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Error extracting profile data: {str(e)}")
        
        # If no data was extracted, return a placeholder
        if not profile_data:
            profile_data['Status'] = 'No profile data found'
        
        return profile_data
    
    def _extract_tweets(self, result):
        """Extract tweets from search results."""
        tweets = []
        
        try:
            # Navigate through the nested structure to get to the entries
            timeline = result.get('result', {}).get('timeline', {})
            instructions = timeline.get('instructions', [])
            
            for instruction in instructions:
                entries = instruction.get('entries', [])
                
                for entry in entries:
                    content = entry.get('content', {})
                    items = content.get('items', [])
                    
                    for item in items:
                        item_content = item.get('item', {}).get('itemContent', {})
                        
                        # Check if this is a tweet
                        if item_content.get('__typename') == 'Tweet':
                            tweet_data = {}
                            
                            # Extract tweet content
                            tweet_results = item_content.get('tweet_results', {}).get('result', {})
                            legacy = tweet_results.get('legacy', {})
                            
                            tweet_data['text'] = legacy.get('full_text', 'N/A')
                            tweet_data['likes'] = legacy.get('favorite_count', 0)
                            tweet_data['retweets'] = legacy.get('retweet_count', 0)
                            tweet_data['replies'] = legacy.get('reply_count', 0)
                            tweet_data['created_at'] = legacy.get('created_at', 'N/A')
                            
                            # Extract author information
                            core = tweet_results.get('core', {})
                            user_results = core.get('user_results', {}).get('result', {})
                            user_legacy = user_results.get('legacy', {})
                            
                            tweet_data['author'] = user_legacy.get('name', 'N/A')
                            tweet_data['author_screen_name'] = user_legacy.get('screen_name', 'N/A')
                            
                            tweets.append(tweet_data)
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Error extracting tweets: {str(e)}")
        
        return tweets
    
    def _extract_user_tweets(self, result):
        """Extract tweets from user timeline."""
        tweets = []
        
        try:
            # Navigate through the nested structure to get to the entries
            timeline = result.get('result', {}).get('timeline', {})
            instructions = timeline.get('instructions', [])
            
            for instruction in instructions:
                entries = instruction.get('entries', [])
                
                for entry in entries:
                    content = entry.get('content', {})
                    
                    # Check if this is a tweet entry
                    if content.get('entryType') == 'TimelineTimelineItem':
                        item_content = content.get('itemContent', {})
                        tweet_results = item_content.get('tweet_results', {}).get('result', {})
                        
                        tweet_data = {}
                        
                        # Extract tweet content
                        legacy = tweet_results.get('legacy', {})
                        
                        tweet_data['text'] = legacy.get('full_text', 'N/A')
                        tweet_data['likes'] = legacy.get('favorite_count', 0)
                        tweet_data['retweets'] = legacy.get('retweet_count', 0)
                        tweet_data['replies'] = legacy.get('reply_count', 0)
                        tweet_data['date'] = legacy.get('created_at', 'N/A')
                        
                        tweets.append(tweet_data)
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/] Error extracting user tweets: {str(e)}")
        
        return tweets
