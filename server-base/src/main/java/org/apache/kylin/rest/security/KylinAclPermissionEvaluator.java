/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

package org.apache.kylin.rest.security;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.apache.kylin.common.KylinConfig;
import org.apache.kylin.common.security.KylinAuthorizationProvider;
import org.apache.kylin.cube.CubeInstance;
import org.apache.kylin.metadata.project.ProjectInstance;
import org.apache.kylin.metadata.project.ProjectManager;
import org.apache.kylin.metadata.realization.RealizationType;
import org.apache.kylin.rest.constant.Constant;
import org.apache.kylin.rest.service.AclService;
import org.springframework.security.acls.AclPermissionEvaluator;
import org.springframework.security.acls.domain.PermissionFactory;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

public class KylinAclPermissionEvaluator extends AclPermissionEvaluator {

    private PermissionFactory kylinPermissionFactory;

    public KylinAclPermissionEvaluator(AclService aclService, PermissionFactory permissionFactory) {
        super(aclService);
        super.setPermissionFactory(permissionFactory);
        this.kylinPermissionFactory = permissionFactory;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        if (targetDomainObject == null) {
            return false;
        }

        KylinConfig kylinConfig= KylinConfig.getInstanceFromEnv();
        if (kylinConfig.isRangerAclEnabled()) {
            String projectName = null;
            String cubeName = null;
            String owner = null;
            String currentUser = authentication.getName();

            if (targetDomainObject instanceof ProjectInstance) {
                ProjectInstance projectInstance = (ProjectInstance) targetDomainObject;
                projectName = projectInstance.getName();
                owner = projectInstance.getOwner();
            } else if (targetDomainObject instanceof CubeInstance) {
                CubeInstance cubeInstance = (CubeInstance) targetDomainObject;
                cubeName = cubeInstance.getName();
                owner = cubeInstance.getOwner();

                List<ProjectInstance> relatedProjectInstances = ProjectManager.getInstance(kylinConfig).findProjects(RealizationType.CUBE, cubeName);
                if (!CollectionUtils.isEmpty(relatedProjectInstances)) {
                    projectName = relatedProjectInstances.get(0).getName();
                }
            } else {
                return super.hasPermission(authentication, targetDomainObject, permission);
            }

            if (owner != null && owner.equalsIgnoreCase(currentUser)) {
                return true;
            }

            List<Permission> permissions = resolveKylinPermission(permission);
            List<String> authorities = getAuthorities(authentication);
            for (Permission p : permissions) {
                String permString = transformPermission(p);
                if (KylinAuthorizationProvider.getInstance(kylinConfig).checkPermission(projectName, cubeName, currentUser, authorities, permString)) {
                    return true;
                }
            }
            return false;
        }

        return super.hasPermission(authentication, targetDomainObject, permission);
    }

    public String transformPermission(Permission p) {
        String permString = null;
        if (p.equals(AclPermission.ADMINISTRATION)) {
            permString = Constant.CUBE_ADMIN;
        } else if (p.equals(AclPermission.MANAGEMENT)) {
            permString = Constant.CUBE_EDIT;
        } else if (p.equals(AclPermission.OPERATION)) {
            permString = Constant.CUBE_OPERATION;
        } else if (p.equals(AclPermission.READ)) {
            permString = (Constant.CUBE_QUERY);
        }
        return permString;
    }

    private List<Permission> resolveKylinPermission(Object permission) {
        if (permission instanceof Integer) {
            return Arrays.asList(kylinPermissionFactory.buildFromMask(((Integer)permission).intValue()));
        }

        if (permission instanceof Permission) {
            return Arrays.asList((Permission)permission);
        }

        if (permission instanceof Permission[]) {
            return Arrays.asList((Permission[])permission);
        }

        if (permission instanceof String) {
            String permString = (String)permission;
            Permission p;

            try {
                p = kylinPermissionFactory.buildFromName(permString);
            } catch(IllegalArgumentException notfound) {
                p = kylinPermissionFactory.buildFromName(permString.toUpperCase());
            }

            if (p != null) {
                return Arrays.asList(p);
            }

        }
        throw new IllegalArgumentException("Unsupported permission: " + permission);
    }

    private List<String> getAuthorities(Authentication authentication) {
        List<String> authorities = new ArrayList<String>();
        for (GrantedAuthority auth : authentication.getAuthorities()) {
            if (!authorities.contains(auth.getAuthority())) {
                authorities.add(auth.getAuthority());
            }
        }
        return authorities;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType,
            Object permission) {
        return super.hasPermission(authentication, targetId, targetType, permission);
    }
}
