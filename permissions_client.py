import requests
import json
from typing import Dict, Any, Optional, List
import logging
import asyncio
import aiohttp
import os
from dotenv import load_dotenv

class KualiPermissionsClient:
    def __init__(self, base_url: str, auth_token: str):
        self.base_url = base_url.rstrip('/')
        self.auth_token = auth_token
        self.graphql_url = f"{self.base_url}/app/api/v0/graphql"
        
    async def get_permissions_data_async(self, session: aiohttp.ClientSession, app_id: str) -> Dict[str, Any]:
        """
        Fetch permissions data for a given app using the PermissionsPage GraphQL query (async).
        
        Args:
            session: The aiohttp session to use for the request
            app_id: The ID of the app to fetch permissions for
            
        Returns:
            Dictionary containing the GraphQL response data
        """
        query = """
        query PermissionsPage($appId: ID!) {
            viewer {
                id
                user {
                    id
                    displayName
                    canManageSettings
                    __typename
                }
                __typename
            }
            app(id: $appId) {
                id
                name
                canAnonymousCreate
                hasDangerousPermissions
                acknowledgedDanger {
                    dateDismissed
                    __typename
                }
                acknowledgedAnonymousRisk {
                    dateDismissed
                    __typename
                }
                pages {
                    id
                    details
                    __typename
                }
                listPolicyGroups {
                    id
                    name
                    description
                    removable
                    policies {
                        id
                        version
                        statements {
                            action
                            resource
                            effect
                            __typename
                        }
                        __typename
                    }
                    identities {
                        type
                        id
                        label
                        __typename
                    }
                    __typename
                }
                __typename
            }
        }
        """
        
        variables = {
            "appId": app_id
        }
        
        headers = {
            "authorization": f"Bearer {self.auth_token}",
            "content-type": "application/json",
            "origin": self.base_url
        }

        payload = {
            "operationName": "PermissionsPage",
            "variables": variables,
            "query": query
        }
        
        async with session.post(self.graphql_url, headers=headers, json=payload) as response:
            response.raise_for_status()
            return await response.json()

    def get_permissions_data(self, app_id: str) -> Dict[str, Any]:
        """
        Fetch permissions data for a given app using the PermissionsPage GraphQL query.
        
        Args:
            app_id: The ID of the app to fetch permissions for
            
        Returns:
            Dictionary containing the GraphQL response data
        """
        query = """
        query PermissionsPage($appId: ID!) {
            viewer {
                id
                user {
                    id
                    displayName
                    canManageSettings
                    __typename
                }
                __typename
            }
            app(id: $appId) {
                id
                name
                canAnonymousCreate
                hasDangerousPermissions
                acknowledgedDanger {
                    dateDismissed
                    __typename
                }
                acknowledgedAnonymousRisk {
                    dateDismissed
                    __typename
                }
                pages {
                    id
                    details
                    __typename
                }
                listPolicyGroups {
                    id
                    name
                    description
                    removable
                    policies {
                        id
                        version
                        statements {
                            action
                            resource
                            effect
                            __typename
                        }
                        __typename
                    }
                    identities {
                        type
                        id
                        label
                        __typename
                    }
                    __typename
                }
                __typename
            }
        }
        """
        
        variables = {
            "appId": app_id
        }
        
        headers = {
            "authorization": f"Bearer {self.auth_token}",
            "content-type": "application/json",
            "origin": self.base_url
        }

        payload = {
            "operationName": "PermissionsPage",
            "variables": variables,
            "query": query
        }
        
        response = requests.post(
            self.graphql_url,
            headers=headers,
            json=payload
        )
        
        response.raise_for_status()
        return response.json()
    
    def get_all_applications(self, space_id: str = "all-apps", suite: str = "build") -> Dict[str, Any]:
        """
        Fetch all applications using the GetSpaceData GraphQL query.
        
        Args:
            space_id: The space ID to fetch apps from (default: "all-apps")
            suite: The suite type (default: "build")
            
        Returns:
            Dictionary containing the GraphQL response data with all applications
        """
        query = """
        query GetSpaceData($spaceId: ID!, $suite: String!) {
            space: spacePortal(id: $spaceId, suite: $suite) {
                id
                apps {
                    id
                    name
                    type
                    firstPageId
                    isFavorite
                    createdAt
                    tileOptions {
                        backgroundColor
                        iconName
                        __typename
                    }
                    viewer {
                        canDuplicate
                        canViewDocuments
                        canSubmitDocuments
                        canManage
                        __typename
                    }
                    __typename
                }
                viewer {
                    id
                    canCreateApps
                    canCreateProducts
                    __typename
                }
                links {
                    id
                    title
                    description
                    url
                    imageUrl
                    createdAt
                    __typename
                }
                __typename
            }
            viewer {
                id
                isKualiAdmin
                __typename
            }
        }
        """
        
        variables = {
            "spaceId": space_id,
            "suite": suite
        }
        
        headers = {
            "authorization": f"Bearer {self.auth_token}",
            "content-type": "application/json",
            "apollographql-operation-name": "GetSpaceData",
            "origin": self.base_url
        }
        
        payload = {
            "operationName": "GetSpaceData",
            "variables": variables,
            "query": query
        }
        
        response = requests.post(
            self.graphql_url,
            headers=headers,
            json=payload
        )
        
        response.raise_for_status()
        return response.json()
    
    def get_kuali_user(self, user_id: str) -> Dict[str, Any]:
        """
        Fetch a single user from the Kuali API.
        
        Args:
            user_id: The ID of the user to fetch
            
        Returns:
            Dictionary containing the user data from /api/v1/users/{id}
        """
        user_url = f"{self.base_url}/api/v1/users/{user_id}"
        headers = {
            "authorization": f"Bearer {self.auth_token}",
            "content-type": "application/json"
        }
        
        response = requests.get(user_url, headers=headers)
        response.raise_for_status()
        return response.json()
    
    async def get_kuali_user_async(self, session: aiohttp.ClientSession, user_id: str) -> Dict[str, Any]:
        """
        Fetch a single user from the Kuali API (async).
        
        Args:
            session: The aiohttp session to use for the request
            user_id: The ID of the user to fetch
            
        Returns:
            Dictionary containing the user data from /api/v1/users/{id}
        """
        user_url = f"{self.base_url}/api/v1/users/{user_id}"
        headers = {
            "authorization": f"Bearer {self.auth_token}",
            "content-type": "application/json"
        }
        
        async with session.get(user_url, headers=headers) as response:
            response.raise_for_status()
            return await response.json()
    
    def get_kuali_group_or_role_members(self, group_or_role_id: str) -> List[Dict[str, Any]]:
        """
        Fetch members of a Kuali group or role.
        If the ID contains ':', treats it as a role ID (group_id:role_identifier).
        Otherwise, treats it as a group ID and looks for the 'members' role.
        
        Args:
            group_or_role_id: Either a group ID or composite role ID (group_id:role_identifier)
            
        Returns:
            List of user dictionaries from the specified group/role
        """
        if ':' in group_or_role_id:
            # Handle as role ID
            group_id, role_identifier = group_or_role_id.split(':', 1)
            target_role_key = 'id'
            target_role_value = role_identifier
            context_name = f"role {group_or_role_id}"
        else:
            # Handle as group ID
            group_id = group_or_role_id
            target_role_key = 'id'
            target_role_value = 'members'
            context_name = f"group {group_id}"
        
        group_url = f"{self.base_url}/api/v1/groups/{group_id}"
        headers = {
            "authorization": f"Bearer {self.auth_token}",
            "content-type": "application/json"
        }
        
        response = requests.get(group_url, headers=headers)
        response.raise_for_status()
        group_data = response.json()
        
        # Find the target role
        roles = group_data.get('roles', [])
        target_role = next((role for role in roles if role.get(target_role_key) == target_role_value), None)
        
        if not target_role:
            logging.warning(f"No role with {target_role_key} '{target_role_value}' found in {context_name}")
            return []
        
        # Get user data for each member
        member_ids = target_role.get('value', [])
        if not member_ids:
            return []
        
        # Use async calls for better performance
        async def fetch_members():
            connector = aiohttp.TCPConnector(limit=100, limit_per_host=50)
            async with aiohttp.ClientSession(connector=connector) as session:
                tasks = []
                for member_id in member_ids:
                    tasks.append(self._fetch_user_safe(session, member_id, context_name))
                
                results = await asyncio.gather(*tasks)
                return [user for user in results if user is not None]
        
        return asyncio.run(fetch_members())
    
    async def _fetch_user_safe(self, session: aiohttp.ClientSession, user_id: str, context: str) -> Optional[Dict[str, Any]]:
        """Helper method to safely fetch a user with error handling."""
        try:
            return await self.get_kuali_user_async(session, user_id)
        except Exception as e:
            logging.exception(f"Failed to get user data for {user_id} in {context}")
            return None
    
    async def resolve_identities_to_users_async(self, session: aiohttp.ClientSession, identities: List[Dict[str, Any]], app_name: str, permission_type: str) -> List[str]:
        """
        Resolve a list of identities (users, roles, groups) to actual user strings (async).
        
        Args:
            session: The aiohttp session to use for requests
            identities: List of identity objects from policy groups
            app_name: Name of the app (for logging purposes)
            permission_type: Type of permission (for logging purposes)
            
        Returns:
            List of user strings in formatted output
        """
        user_tasks = []
        
        for identity in identities:
            identity_type = identity.get('type')
            identity_id = identity.get('id')
            identity_label = identity.get('label')
            
            if identity_type == 'USER':
                user_tasks.append(self._fetch_user_safe(session, identity_id, f"{permission_type} for {app_name}"))
            elif identity_type in ['ROLE', 'GROUP']:
                try:
                    # Get group/role members (this part is still sync but much less of the bottleneck)
                    group_users = self.get_kuali_group_or_role_members(identity_id)
                    # Add tasks for users that weren't already fetched by the group/role method
                    for user in group_users:
                        if user:  # Only add non-None users
                            user_tasks.append(asyncio.create_task(self._return_user(user)))
                except Exception as e:
                    logging.exception(f"Failed to get members for {identity_type} {identity_id}")
            else:
                logging.warning(f"{identity_type} {identity_label} has {permission_type} access on app {app_name}.")
        
        # Fetch all users concurrently
        if user_tasks:
            users = await asyncio.gather(*user_tasks)
            users = [user for user in users if user is not None]
        else:
            users = []
        
        # Convert user objects to formatted strings
        user_strings = []
        for user in users:
            user_id = user.get('id')
            user_email = user.get('email', 'no-email')
            user_school_id = user.get('schoolId', 'no-school-id')
            display_name = user.get('displayName', user.get('name', 'Unknown'))
            user_strings.append(f"{user_email}: {display_name} ({user_school_id}) [{user_id}]")
        
        return user_strings
    
    async def _return_user(self, user: Dict[str, Any]) -> Dict[str, Any]:
        """Helper method to return a user object as a coroutine."""
        return user
    
    def resolve_identities_to_users(self, identities: List[Dict[str, Any]], app_name: str, permission_type: str) -> List[str]:
        """
        Resolve a list of identities (users, roles, groups) to actual user strings (sync wrapper).
        
        Args:
            identities: List of identity objects from policy groups
            app_name: Name of the app (for logging purposes)
            permission_type: Type of permission (for logging purposes)
            
        Returns:
            List of user strings in formatted output
        """
        async def resolve_async():
            connector = aiohttp.TCPConnector(limit=100, limit_per_host=50)
            async with aiohttp.ClientSession(connector=connector) as session:
                return await self.resolve_identities_to_users_async(session, identities, app_name, permission_type)
        
        return asyncio.run(resolve_async())
    
    def evaluate_permissions_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate and process the permissions data returned from the GraphQL query.
        
        Args:
            data: Raw GraphQL response data
            
        Returns:
            Simplified permissions report with only requested data
        """
        if 'errors' in data:
            return {
                'success': False,
                'errors': data['errors']
            }
        
        response_data = data.get('data', {})
        app_data = response_data.get('app', {})
        
        admin_users = []
        read_document_users = []
        
        # Extract users with specific permissions from policy groups
        policy_groups = app_data.get('listPolicyGroups', [])
        
        for group in policy_groups:
            identities = group.get('identities', [])
            policies = group.get('policies', [])
            
            for policy in policies:
                statements = policy.get('statements', [])
                
                for statement in statements:
                    actions = statement.get('action')
                    effect = statement.get('effect', '').lower()
                    
                    if effect == 'allow':
                        if 'apps:administer' in actions:
                            user_strings = self.resolve_identities_to_users(identities, app_data.get('name'), 'ADMIN')
                            admin_users.extend(user_strings)
                        elif 'apps:readDocuments' in actions:
                            user_strings = self.resolve_identities_to_users(identities, app_data.get('name'), 'READ_DOCUMENTS')
                            read_document_users.extend(user_strings)
        
        # Remove duplicates while preserving order
        admin_users = list(set(admin_users))
        read_document_users = list(set(read_document_users))
        
        return {
            'success': True,
            'app_id': app_data.get('id'),
            'app_name': app_data.get('name'),
            'accepts_anonymous_submissions': app_data.get('canAnonymousCreate', False),
            'admin_users': admin_users,
            'read_document_users': read_document_users
        }
    
    def get_and_evaluate_permissions(self, app_id: str) -> Dict[str, Any]:
        """
        Convenience method to fetch and evaluate permissions data in one call.
        
        Args:
            app_id: The ID of the app to fetch permissions for
            
        Returns:
            Processed permissions analysis
        """
        raw_data = self.get_permissions_data(app_id)
        return self.evaluate_permissions_data(raw_data)
    
    async def _process_app_batch(self, session: aiohttp.ClientSession, apps_batch: List[Dict[str, Any]]) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Process a batch of apps concurrently to get their permissions data.
        
        Args:
            session: The aiohttp session to use for requests
            apps_batch: List of app dictionaries to process
            
        Returns:
            Tuple of (successful_reports, failed_apps)
        """
        async def process_single_app(app):
            app_id = app.get('id')
            app_name = app.get('name', 'Unknown')
            
            try:
                raw_data = await self.get_permissions_data_async(session, app_id)
                report = self.evaluate_permissions_data(raw_data)
                
                if report.get('success'):
                    return ('success', report)
                else:
                    return ('failed', {
                        'app_id': app_id,
                        'app_name': app_name,
                        'error': report.get('errors', 'Unknown error')
                    })
            except Exception as e:
                logging.exception(f"Failed to get permissions for {app_name} ({app_id})")
                return ('failed', {
                    'app_id': app_id,
                    'app_name': app_name,
                    'error': str(e)
                })
        
        # Process all apps in this batch concurrently
        results = await asyncio.gather(*[process_single_app(app) for app in apps_batch])
        
        successful_reports = []
        failed_apps = []
        
        for status, data in results:
            if status == 'success':
                successful_reports.append(data)
            else:
                failed_apps.append(data)
        
        return successful_reports, failed_apps

    async def generate_all_permissions_report_async(self, space_id: str = "all-apps", suite: str = "build", batch_size: int = 30) -> Dict[str, Any]:
        """
        Generate permissions reports for all applications in a space (async with batching).
        
        Args:
            space_id: The space ID to fetch apps from (default: "all-apps")
            suite: The suite type (default: "build")
            batch_size: Number of concurrent requests per batch (default: 30)
            
        Returns:
            Dictionary containing permissions reports for all applications
        """
        logging.info("Fetching all applications...")
        apps_data = self.get_all_applications(space_id, suite)
        
        if 'errors' in apps_data:
            return {
                'success': False,
                'errors': apps_data['errors']
            }
        
        space_data = apps_data.get('data', {}).get('space', {})
        apps = space_data.get('apps', [])
        
        logging.info(f"Found {len(apps)} applications. Generating permissions reports with {batch_size} concurrent requests...")
        
        all_reports = []
        all_failed_apps = []
        
        # Create batches of apps
        app_batches = [apps[i:i + batch_size] for i in range(0, len(apps), batch_size)]
        
        connector = aiohttp.TCPConnector(limit=100, limit_per_host=50)
        async with aiohttp.ClientSession(connector=connector) as session:
            for batch_num, apps_batch in enumerate(app_batches, 1):
                logging.info(f"Processing batch {batch_num}/{len(app_batches)} ({len(apps_batch)} apps)")
                
                try:
                    reports, failed_apps = await self._process_app_batch(session, apps_batch)
                    all_reports.extend(reports)
                    all_failed_apps.extend(failed_apps)
                    
                    logging.info(f"Batch {batch_num} complete: {len(reports)} successful, {len(failed_apps)} failed")
                except Exception as e:
                    logging.exception(f"Error processing batch {batch_num}")
                    # Add all apps in this batch to failed list
                    for app in apps_batch:
                        all_failed_apps.append({
                            'app_id': app.get('id'),
                            'app_name': app.get('name', 'Unknown'),
                            'error': f"Batch processing error: {str(e)}"
                        })
        
        return {
            'success': True,
            'total_apps': len(apps),
            'successful_reports': len(all_reports),
            'failed_reports': len(all_failed_apps),
            'reports': all_reports,
            'failed_apps': all_failed_apps
        }

    def generate_all_permissions_report(self, space_id: str = "all-apps", suite: str = "build") -> Dict[str, Any]:
        """
        Generate permissions reports for all applications in a space (sync version).
        
        Args:
            space_id: The space ID to fetch apps from (default: "all-apps")
            suite: The suite type (default: "build")
            
        Returns:
            Dictionary containing permissions reports for all applications
        """
        return asyncio.run(self.generate_all_permissions_report_async(space_id, suite))


def main():
    """
    Example usage of the KualiPermissionsClient
    """
    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Load configuration from environment variables
    load_dotenv()
    base_url = os.getenv('KUALI_BASE_URL')
    auth_token = os.getenv('KUALI_AUTH_TOKEN')
    
    if not base_url or not auth_token:
        logging.error("Missing required environment variables. Please set KUALI_BASE_URL and KUALI_AUTH_TOKEN in your .env file.")
        return
    
    client = KualiPermissionsClient(base_url, auth_token)
    
    try:
        # Generate permissions report for all applications
        all_reports = client.generate_all_permissions_report()
        print(json.dumps(all_reports, indent=2))
    except requests.RequestException as e:
        logging.exception(f"Error making request: {e}")
    except Exception as e:
        logging.exception(f"Error processing data: {e}")

if __name__ == "__main__":
    main()