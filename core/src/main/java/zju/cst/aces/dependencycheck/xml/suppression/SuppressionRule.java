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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package zju.cst.aces.dependencycheck.xml.suppression;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import javax.annotation.concurrent.NotThreadSafe;
import org.apache.commons.lang3.time.DateFormatUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author Jeremy Long
 */
@NotThreadSafe
public class SuppressionRule {

    /**
     * The Logger for use throughout the class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(SuppressionRule.class);
    /**
     * The file path for the suppression.
     */
    private PropertyType filePath;

    /**
     * The SHA1 hash.
     */
    private String sha1;
    /**
     * A list of CPEs to suppression
     */
    private List<PropertyType> cpe = new ArrayList<>();
    /**
     * The list of cvssBelow scores.
     */
    private List<Float> cvssBelow = new ArrayList<>();
    /**
     * The list of CWE entries to suppress.
     */
    private List<String> cwe = new ArrayList<>();
    /**
     * The list of CVE entries to suppress.
     */
    private List<String> cve = new ArrayList<>();
    /**
     * The list of vulnerability name entries to suppress.
     */
    private final List<PropertyType> vulnerabilityNames = new ArrayList<>();
    /**
     * A Maven GAV to suppression.
     */
    private PropertyType gav = null;
    /**
     * The list of vulnerability name entries to suppress.
     */
    private PropertyType packageUrl = null;
    /**
     * The notes added in suppression file
     */

    private String notes;

    /**
     * A flag indicating whether or not the suppression rule is a core/base rule
     * that should not be included in the resulting report in the "suppressed"
     * section.
     */
    private boolean base;

    /**
     * A date until which the suppression is to be retained. This can be used to
     * make a temporary suppression that auto-expires to suppress a CVE while
     * waiting for the vulnerability fix of the dependency to be released.
     */
    private Calendar until;

    /**
     * A flag whether or not the rule matched a dependency & CPE.
     */
    private boolean matched = false;

    /**
     * Get the value of matched.
     *
     * @return the value of matched
     */
    public boolean isMatched() {
        return matched;
    }

    /**
     * Set the value of matched.
     *
     * @param matched new value of matched
     */
    public void setMatched(boolean matched) {
        this.matched = matched;
    }

    /**
     * Get the (@code{nullable}) value of until.
     *
     * @return the value of until
     */
    public Calendar getUntil() {
        return until;
    }

    /**
     * Set the value of until.
     *
     * @param until new value of until
     */
    public void setUntil(Calendar until) {
        this.until = until;
    }

    /**
     * Get the value of filePath.
     *
     * @return the value of filePath
     */
    public PropertyType getFilePath() {
        return filePath;
    }

    /**
     * Set the value of filePath.
     *
     * @param filePath new value of filePath
     */
    public void setFilePath(PropertyType filePath) {
        this.filePath = filePath;
    }

    /**
     * Get the value of sha1.
     *
     * @return the value of sha1
     */
    public String getSha1() {
        return sha1;
    }

    /**
     * Set the value of SHA1.
     *
     * @param sha1 new value of SHA1
     */
    public void setSha1(String sha1) {
        this.sha1 = sha1;
    }

    /**
     * Get the value of CPE.
     *
     * @return the value of CPE
     */
    public List<PropertyType> getCpe() {
        return cpe;
    }

    /**
     * Set the value of CPE.
     *
     * @param cpe new value of CPE
     */
    public void setCpe(List<PropertyType> cpe) {
        this.cpe = cpe;
    }

    /**
     * Adds the CPE to the CPE list.
     *
     * @param cpe the CPE to add
     */
    public void addCpe(PropertyType cpe) {
        this.cpe.add(cpe);
    }

    /**
     * Adds the CPE to the CPE list.
     *
     * @param name the vulnerability name to add
     */
    public void addVulnerabilityName(PropertyType name) {
        this.vulnerabilityNames.add(name);
    }

    /**
     * Get the value of cvssBelow.
     *
     * @return the value of cvssBelow
     */
    public List<Float> getCvssBelow() {
        return cvssBelow;
    }

    /**
     * Set the value of cvssBelow.
     *
     * @param cvssBelow new value of cvssBelow
     */
    public void setCvssBelow(List<Float> cvssBelow) {
        this.cvssBelow = cvssBelow;
    }

    /**
     * Adds the CVSS to the cvssBelow list.
     *
     * @param cvss the CVSS to add
     */
    public void addCvssBelow(Float cvss) {
        this.cvssBelow.add(cvss);
    }

    /**
     * Get the value of notes.
     *
     * @return the value of notes
     */
    public String getNotes() {
        return notes;
    }

    /**
     * Set the value of notes.
     *
     * @param notes new value of cve
     */
    public void setNotes(String notes) {
        this.notes = notes;
    }

    /**
     * Adds the notes to the cve list.
     *
     * @param notes the cve to add
     */
    public void addNotes(String notes) {
        this.notes = notes;
    }

    /**
     * Returns whether this suppression rule has notes entries.
     *
     * @return whether this suppression rule has notes entries
     */
    public boolean hasNotes() {
        return !cve.isEmpty();
    }

    /**
     * Get the value of CWE.
     *
     * @return the value of CWE
     */
    public List<String> getCwe() {
        return cwe;
    }

    /**
     * Set the value of CWE.
     *
     * @param cwe new value of CWE
     */
    public void setCwe(List<String> cwe) {
        this.cwe = cwe;
    }

    /**
     * Adds the CWE to the CWE list.
     *
     * @param cwe the CWE to add
     */
    public void addCwe(String cwe) {
        this.cwe.add(cwe);
    }

    /**
     * Get the value of CVE.
     *
     * @return the value of CVE
     */
    public List<String> getCve() {
        return cve;
    }

    /**
     * Set the value of CVE.
     *
     * @param cve new value of CVE
     */
    public void setCve(List<String> cve) {
        this.cve = cve;
    }

    /**
     * Adds the CVE to the CVE list.
     *
     * @param cve the CVE to add
     */
    public void addCve(String cve) {
        this.cve.add(cve);
    }

    /**
     * Get the value of Maven GAV.
     *
     * @return the value of GAV
     */
    public PropertyType getGav() {
        return gav;
    }

    /**
     * Set the value of Maven GAV.
     *
     * @param gav new value of Maven GAV
     */
    public void setGav(PropertyType gav) {
        this.gav = gav;
    }

    /**
     * Set the value of Package URL.
     *
     * @param purl new value of package URL
     */
    public void setPackageUrl(PropertyType purl) {
        this.packageUrl = purl;
    }

    /**
     * Get the value of base.
     *
     * @return the value of base
     */
    public boolean isBase() {
        return base;
    }

    /**
     * Set the value of base.
     *
     * @param base new value of base
     */
    public void setBase(boolean base) {
        this.base = base;
    }

    /**
     * Identifies if the cpe specified by the cpe suppression rule does not
     * specify a version.
     *
     * @param c a suppression rule identifier
     * @return true if the property type does not specify a version; otherwise
     * false
     */
    protected boolean cpeHasNoVersion(PropertyType c) {
        return !c.isRegex() && countCharacter(c.getValue(), ':') <= 3;
    }

    /**
     * Counts the number of occurrences of the character found within the
     * string.
     *
     * @param str the string to check
     * @param c the character to count
     * @return the number of times the character is found in the string
     */
    private int countCharacter(String str, char c) {
        int count = 0;
        int pos = str.indexOf(c) + 1;
        while (pos > 0) {
            count += 1;
            pos = str.indexOf(c, pos) + 1;
        }
        return count;
    }

    /**
     * Standard toString implementation.
     *
     * @return a string representation of this object
     */
    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder(64);
        sb.append("SuppressionRule{");
        if (until != null) {
            final String dt = DateFormatUtils.ISO_8601_EXTENDED_DATETIME_TIME_ZONE_FORMAT.format(until);
            sb.append("until=").append(dt).append(',');
        }
        if (filePath != null) {
            sb.append("filePath=").append(filePath).append(',');
        }
        if (sha1 != null) {
            sb.append("sha1=").append(sha1).append(',');
        }
        if (packageUrl != null) {
            sb.append("packageUrl=").append(packageUrl).append(',');
        }
        if (gav != null) {
            sb.append("gav=").append(gav).append(',');
        }
        if (cpe != null && !cpe.isEmpty()) {
            sb.append("cpe={");
            cpe.forEach((pt) -> sb.append(pt).append(','));
            sb.append('}');
        }
        if (cwe != null && !cwe.isEmpty()) {
            sb.append("cwe={");
            cwe.forEach((s) -> sb.append(s).append(','));
            sb.append('}');
        }
        if (cve != null && !cve.isEmpty()) {
            sb.append("cve={");
            cve.forEach((s) -> sb.append(s).append(','));
            sb.append('}');
        }
        if (vulnerabilityNames != null && !vulnerabilityNames.isEmpty()) {
            sb.append("vulnerabilityName={");
            vulnerabilityNames.forEach((pt) -> sb.append(pt).append(','));
            sb.append('}');
        }
        if (cvssBelow != null && !cvssBelow.isEmpty()) {
            sb.append("cvssBelow={");
            cvssBelow.forEach((s) -> sb.append(s).append(','));
            sb.append('}');
        }
        sb.append('}');
        return sb.toString();
    }
}
