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
package zju.cst.aces.dependencycheck.xml.assembly;

import java.io.IOException;
import javax.annotation.concurrent.ThreadSafe;

/**
 * An exception used when parsing a grok assembly XML file fails.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class GrokParseException extends IOException {

    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = 8169031327810508998L;

    /**
     * Creates a new GrokParseException.
     */
    public GrokParseException() {
        super();
    }

    /**
     * Creates a new GrokParseException.
     *
     * @param msg a message for the exception.
     */
    public GrokParseException(String msg) {
        super(msg);
    }

    /**
     * Creates a new GrokParseException.
     *
     * @param ex the cause of the parse exception
     */
    public GrokParseException(Throwable ex) {
        super(ex);
    }

    /**
     * Creates a new GrokParseException.
     *
     * @param msg a message for the exception.
     * @param ex the cause of the parse exception
     */
    public GrokParseException(String msg, Throwable ex) {
        super(msg, ex);
    }
}
