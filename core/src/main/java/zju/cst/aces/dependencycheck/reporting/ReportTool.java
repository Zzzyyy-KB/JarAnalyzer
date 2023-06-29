/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2018 Jeremy Long. All Rights Reserved.
 */
package zju.cst.aces.dependencycheck.reporting;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import zju.cst.aces.dependencycheck.dependency.Dependency;
import zju.cst.aces.dependencycheck.dependency.naming.CpeIdentifier;
import zju.cst.aces.dependencycheck.dependency.naming.GenericIdentifier;
import zju.cst.aces.dependencycheck.dependency.naming.Identifier;
import zju.cst.aces.dependencycheck.dependency.naming.PurlIdentifier;
import zju.cst.aces.dependencycheck.utils.SeverityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.exceptions.CpeEncodingException;
import us.springett.parsers.cpe.util.Convert;

/**
 * Utilities to format items in the Velocity reports.
 *
 * @author Jeremy Long
 */
public class ReportTool {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(ReportTool.class);

    /**
     * Estimates the CVSS V2 score for the given severity.
     *
     * @param severity the text representation of a score
     * @return the estimated score
     */
    public float estimateSeverity(String severity) {
        return SeverityUtil.estimateCvssV2(severity);
    }

}
