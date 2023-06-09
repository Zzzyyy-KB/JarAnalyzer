/*
 * This file is part of dependency-check-utils.
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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package zju.cst.aces.dependencycheck.utils;

import java.io.IOException;

/**
 * An exception used when an error occurs reading a setting.
 *
 * @author Jeremy Long
 * @version $Id: $Id
 */
public class InvalidSettingException extends IOException {

    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = 5189805248759495398L;

    /**
     * Creates a new InvalidSettingException.
     */
    public InvalidSettingException() {
        super();
    }

    /**
     * Creates a new InvalidSettingException.
     *
     * @param msg a message for the exception.
     */
    public InvalidSettingException(String msg) {
        super(msg);
    }

    /**
     * Creates a new InvalidSettingException.
     *
     * @param ex the cause of the setting exception.
     */
    public InvalidSettingException(Throwable ex) {
        super(ex);
    }

    /**
     * Creates a new InvalidSettingException.
     *
     * @param msg a message for the exception.
     * @param ex the cause of the setting exception.
     */
    public InvalidSettingException(String msg, Throwable ex) {
        super(msg, ex);
    }
}
