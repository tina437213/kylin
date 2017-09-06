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

import java.util.ArrayList;
import java.util.List;

import org.apache.kylin.common.KylinConfig;
import org.apache.kylin.common.persistence.AclEntity;
import org.apache.kylin.cube.CubeManager;
import org.apache.kylin.metadata.project.ProjectManager;
import org.apache.kylin.rest.constant.Constant;
import org.apache.kylin.rest.response.AccessEntryResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component("externalAuthorizationProvider")
public class ExternalAuthorizationProvider {

    @Autowired
    private KylinAclPermissionEvaluator kylinAclPermissionEvaluator;

    private final Permission[] allPermissions = { AclPermission.ADMINISTRATION, AclPermission.MANAGEMENT, AclPermission.OPERATION, AclPermission.READ };

    public List<AccessEntryResponse> getAcl(String type, String uuid) {
        List<AccessEntryResponse> result = new ArrayList<AccessEntryResponse>();
        if (uuid == null) {
            return result;
        }

        AclEntity ae = null;
        KylinConfig config = KylinConfig.getInstanceFromEnv();
        if (type.equals(AclEntityType.PROJECT_INSTANCE)) {
            ae = ProjectManager.getInstance(config).getProjectByUuid(uuid);
        } else if (type.equals(AclEntityType.CUBE_INSTANCE)) {
            ae = CubeManager.getInstance(config).getCubeByUuid(uuid);
        }

        if (ae != null) {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Sid sid = new PrincipalSid(authentication.getName());
            for (Permission permission : allPermissions) {
                if (kylinAclPermissionEvaluator.hasPermission(authentication, ae, permission)) {
                    String permString =  kylinAclPermissionEvaluator.transformPermission(permission);
                    result = generateAceResponses(permString, sid);
                    break;
                }
            }
        }

        return result;
    }

    private List<AccessEntryResponse> generateAceResponses(String permission, Sid sid) {
        List<AccessEntryResponse> result = new ArrayList<AccessEntryResponse>();
        switch (permission) {
        case Constant.CUBE_ADMIN:
            result.add(new AccessEntryResponse(null, sid, AclPermission.ADMINISTRATION, true));
        case Constant.CUBE_EDIT:
            result.add(new AccessEntryResponse(null, sid, AclPermission.MANAGEMENT, true));
        case Constant.CUBE_OPERATION:
            result.add(new AccessEntryResponse(null, sid, AclPermission.OPERATION, true));
        case Constant.CUBE_QUERY:
            result.add(new AccessEntryResponse(null, sid, AclPermission.READ, true));
        default:
            break;
        }
        return result;
    }

}
