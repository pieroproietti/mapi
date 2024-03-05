from openapi_core import OpenAPI

openapi = OpenAPI.from_file_path('metadefender-core.json')

# raises error if request is invalid
result = openapi.unmarshal_request(request)

# get parameters
path_params = result.parameters.path
query_params = result.parameters.query
cookies_params = result.parameters.cookies
headers_params = result.parameters.headers
# get body
body = result.body
# get security data
security = result.security

# https://github.com/koxudaxi/datamodel-code-generator
