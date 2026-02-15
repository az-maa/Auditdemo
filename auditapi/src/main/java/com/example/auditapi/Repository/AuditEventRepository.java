package com.example.auditapi.Repository;

import com.example.auditapi.Model.AuditEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AuditEventRepository extends JpaRepository<AuditEvent, Long> {

    
    List<AuditEvent> findByEventType(String eventType);

    List<AuditEvent> findByUserId(String userId);

   
    List<AuditEvent> findByStatus(String status);

    
    List<AuditEvent> findBySeverity(String severity);

    
    List<AuditEvent> findByTimestampBetween(LocalDateTime start, LocalDateTime end);

    
    @Query("SELECT COUNT(e) FROM AuditEvent e WHERE e.eventType = ?1")
    long countByEventType(String eventType);

    
    @Query("SELECT COUNT(e) FROM AuditEvent e WHERE e.status = ?1")
    long countByStatus(String status);

    
    @Query("SELECT COUNT(e) FROM AuditEvent e WHERE e.severity = ?1")
    long countBySeverity(String severity);
}