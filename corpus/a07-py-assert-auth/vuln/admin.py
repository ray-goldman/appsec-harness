def delete_tenant(user, tenant):
    assert user.is_admin, "admins only"
    tenant.delete()
