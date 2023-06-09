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
 * Copyright (c) 2019 Jeremy Long. All Rights Reserved.
 */
package zju.cst.aces.dependencycheck.exception;

import javax.annotation.concurrent.ThreadSafe;

/**
 * An exception thrown when a parsing error occurs.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class ParseException extends Exception {

    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = 1158867461225495484L;

    /**
     * Creates a new ParseException.
     */
    public ParseException() {
        super();
    }

    /**
     * Creates a new ParseException.
     *
     * @param msg a message for the exception.
     */
    public ParseException(String msg) {
        super(msg);
    }

    /**
     * Creates a new ParseException.
     *
     * @param ex the cause of the failure.
     */
    public ParseException(Throwable ex) {
        super(ex);
    }

    /**
     * Creates a new ParseException.
     *
     * @param msg a message for the exception.
     * @param ex the cause of the failure.
     */
    public ParseException(String msg, Throwable ex) {
        super(msg, ex);
    }
}
