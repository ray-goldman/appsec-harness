class PermissionDenied(Exception):
    pass

def delete_tenant(user, tenant):
    if not user.is_admin:
        raise PermissionDenied("admins only")
    tenant.delete()
