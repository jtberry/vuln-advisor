"""auth/ -- Authentication and authorization package for VulnAdvisor.

Layer rule: auth/ imports only stdlib + third-party libraries.
It does NOT import from api/, web/, core/, cmdb/, or cache/.
api/ and web/ import from auth/, not the other way around.
"""
