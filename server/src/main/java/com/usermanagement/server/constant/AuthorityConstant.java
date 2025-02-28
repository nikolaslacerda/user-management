package com.usermanagement.server.constant;

public class AuthorityConstant {
    public static final String[] USER_AUTHORITIES = {"user:read"};
    public static final String[] HR_AUTHORITIES = {"user:read", "user:update"};
    public static final String[] MANAGER_AUTHORITIES = {"user:read", "user:update"};
    public static final String[] ADMIN_AUTHORITIES = {"user:create", "user:read", "user:update"};
    public static final String[] SUPER_ADMIN_AUTHORITIES = {"user:create", "user:read", "user:update", "user:delete"};
}
