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

import org.apache.coyote.InputBuffer;
import org.apache.tomcat.util.net.ApplicationBufferHandler;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * An {@link InputBuffer} decorator that copies the request body as the application reads it.
 * <p>
 * This is deliberately a pass-through tee rather than a reader: the bytes are handed to the
 * delegate first and only then duplicated into a local buffer, so the application still receives
 * the complete, untouched body. Nothing is consumed on the application's behalf, which is what
 * makes the valve safe to leave enabled on a live endpoint.
 * <p>
 * One instance is created per instrumented request, so no synchronisation is required.
 */
final class CapturingInputBuffer implements InputBuffer {

    private final InputBuffer delegate;
    private final int maxBytes;
    private final ByteArrayOutputStream captured;
    private boolean truncated;
    private boolean captureFailed;

    /**
     * @param delegate the buffer currently installed on the coyote request; never {@code null}
     * @param maxBytes hard cap on the number of body bytes retained for logging
     */
    CapturingInputBuffer(InputBuffer delegate, int maxBytes) {

        this.delegate = delegate;
        this.maxBytes = maxBytes;
        this.captured = new ByteArrayOutputStream(Math.min(maxBytes, 1024));
    }

    @Override
    public int doRead(ApplicationBufferHandler handler) throws IOException {

        int read = delegate.doRead(handler);
        if (read > 0) {
            capture(handler);
        }
        return read;
    }

    @Override
    public int available() {

        return delegate.available();
    }

    /**
     * Copies the chunk the delegate just produced. The handler's buffer is duplicated before
     * reading so that the position and limit the connector relies on are left untouched.
     * <p>
     * Capture failures are recorded and swallowed: a diagnostic valve must never turn a working
     * request into a failed one.
     */
    private void capture(ApplicationBufferHandler handler) {

        try {
            ByteBuffer source = handler.getByteBuffer();
            if (source == null) {
                return;
            }
            ByteBuffer copy = source.duplicate();
            int available = copy.remaining();
            int room = maxBytes - captured.size();
            if (room <= 0) {
                truncated = truncated || available > 0;
                return;
            }
            int toCopy = Math.min(available, room);
            byte[] chunk = new byte[toCopy];
            copy.get(chunk);
            captured.write(chunk, 0, toCopy);
            if (available > toCopy) {
                truncated = true;
            }
        } catch (Throwable t) {
            captureFailed = true;
        }
    }

    /**
     * @return the captured body bytes; empty when the application never read the body
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
