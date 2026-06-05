1. Implement `AuditEventEmitter.__init__` in `nautilus/rkm/audit_emitter.py` — stores `audit_logger` and per-instance buffer list
2. Implement `AuditEventEmitter.queue(event_type, *, fields)` — appends `(event_type, fields)` to buffer, swallows exceptions
3. Implement `AuditEventEmitter.flush(*, trace_id, session_id)` — drains buffer, calls `audit_logger.emit_event(entry)` per item, returns count
4. Implement `emit_event_oob` — direct call to `audit_logger.emit_event(entry)`  
5. Add `AuditLogger.emit_event(entry)` method in `audit_logger.py` that delegates to existing `emit()` — backward compat preserved
6. Risks: tests use `_RecordingLogger` mock with `emit_event(entry: Any)` — emitter must call `emit_event`, not `emit`
