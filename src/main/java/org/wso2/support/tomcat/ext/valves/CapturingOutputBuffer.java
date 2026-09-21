/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.support.tomcat.ext.valves;

import org.apache.coyote.OutputBuffer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * An {@link OutputBuffer} decorator that copies the response body as the application writes it.
 * <p>
 * The chunk is duplicated <i>before</i> it is handed to the delegate, because the delegate
 * consumes it. As with {@link CapturingInputBuffer}, the copy never alters what reaches the wire.
 * <p>
 * One instance is created per instrumented request, so no synchronisation is required.
 */
final class CapturingOutputBuffer implements OutputBuffer {

    private final OutputBuffer delegate;
    private final int maxBytes;
    private final ByteArrayOutputStream captured;
    private boolean truncated;
    private boolean captureFailed;

    /**
     * @param delegate the buffer currently installed on the coyote response; never {@code null}
     * @param maxBytes hard cap on the number of body bytes retained for logging
     */
    CapturingOutputBuffer(OutputBuffer delegate, int maxBytes) {

        this.delegate = delegate;
        this.maxBytes = maxBytes;
        this.captured = new ByteArrayOutputStream(Math.min(maxBytes, 1024));
    }

    @Override
    public int doWrite(ByteBuffer chunk) throws IOException {

        capture(chunk);
        return delegate.doWrite(chunk);
    }

    @Override
    public long getBytesWritten() {

        return delegate.getBytesWritten();
    }

    /**
     * Copies the chunk about to be written. Capture failures are recorded and swallowed so that a
     * diagnostic valve can never break response writing.
     */
    private void capture(ByteBuffer chunk) {

        try {
            if (chunk == null) {
                return;
            }
            ByteBuffer copy = chunk.duplicate();
            int available = copy.remaining();
            int room = maxBytes - captured.size();
            if (room <= 0) {
                truncated = truncated || available > 0;
                return;
            }
            int toCopy = Math.min(available, room);
            byte[] bytes = new byte[toCopy];
            copy.get(bytes);
            captured.write(bytes, 0, toCopy);
            if (available > toCopy) {
                truncated = true;
            }
        } catch (Throwable t) {
            captureFailed = true;
        }
    }

    /**
     * @return the captured body bytes; empty when the application wrote no body
     */
    byte[] getCapturedBytes() {

        return captured.toByteArray();
    }

    /**
     * @return {@code true} when the body was larger than the configured cap
     */
    boolean isTruncated() {

        return truncated;
    }

    /**
     * @return {@code true} when at least one chunk could not be copied
     */
    boolean isCaptureFailed() {

        return captureFailed;
    }
}
