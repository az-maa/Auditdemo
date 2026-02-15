package com.example.auditapi.Controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.cdimascio.dotenv.Dotenv;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/api/audit")
@CrossOrigin(origins = "*")
public class AgentController {

    private static final String AGENT_SCRIPT_PATH =
            "C:/Users/cooki/AWB/AuditDemo/audit-agent/audit_agent.py";

    
    private static final Dotenv dotenv = Dotenv.configure()
            .ignoreIfMissing()   
            .load();

    private static String env(String key) {
        
        String val = dotenv.get(key, null);
        return val != null ? val : System.getenv(key);
    }

    private final ObjectMapper mapper = new ObjectMapper();

    @PostMapping("/ask")
    public ResponseEntity<Map<String, Object>> askAgent(@RequestBody Map<String, String> body) {
        String question = body.getOrDefault("question", "").trim();
        Map<String, Object> response = new HashMap<>();

        if (question.isEmpty()) {
            response.put("answer", "Please provide a question.");
            response.put("steps", Collections.emptyList());
            return ResponseEntity.badRequest().body(response);
        }

        try {
            ProcessBuilder pb = new ProcessBuilder("python", AGENT_SCRIPT_PATH);
            pb.redirectErrorStream(true);

            Map<String, String> envMap = pb.environment();
            envMap.put("PYTHONIOENCODING", "utf-8");
            envMap.put("PYTHONUTF8",       "1");
            envMap.put("PG_HOST",          env("PG_HOST"));
            envMap.put("PG_PORT",          env("PG_PORT"));
            envMap.put("PG_DATABASE",      env("PG_DATABASE"));
            envMap.put("PG_USER",          env("PG_USER"));
            envMap.put("PG_PASSWORD",      env("PG_PASSWORD"));
            envMap.put("GROQ_API_KEY",     env("GROQ_API_KEY"));

            Process process = pb.start();

            byte[] input = (question + "\nquit\n").getBytes(StandardCharsets.UTF_8);
            process.getOutputStream().write(input);
            process.getOutputStream().flush();
            process.getOutputStream().close();

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8)
            );

            List<String> stepJsonLines = new ArrayList<>();
            StringBuilder otherOutput  = new StringBuilder();

            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("STEP_JSON:")) {
                    stepJsonLines.add(line.substring("STEP_JSON:".length()).trim());
                } else {
                    otherOutput.append(line).append("\n");
                }
            }

            boolean finished = process.waitFor(90, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                response.put("answer", "Agent timed out.");
                response.put("steps", Collections.emptyList());
                return ResponseEntity.ok(response);
            }

            List<Map<String, Object>> steps = new ArrayList<>();
            String answer = null;

            for (String json : stepJsonLines) {
                try {
                    JsonNode node = mapper.readTree(json);
                    String type = node.has("type") ? node.get("type").asText() : "";

                    if ("final".equals(type)) {
                        if (node.has("answer")) answer = node.get("answer").asText();
                        if (node.has("steps")) {
                            for (JsonNode s : node.get("steps")) {
                                steps.add(mapper.convertValue(s, Map.class));
                            }
                        }
                    } else if ("step".equals(type)) {
                        Map<String, Object> stepMap = new LinkedHashMap<>();
                        if (node.has("thought")) stepMap.put("thought", node.get("thought").asText());
                        if (node.has("tools")) {
                            List<Map<String, Object>> tools = new ArrayList<>();
                            for (JsonNode t : node.get("tools")) {
                                Map<String, Object> toolMap = new LinkedHashMap<>();
                                toolMap.put("tool",   t.has("tool")   ? t.get("tool").asText()   : "");
                                toolMap.put("result", t.has("result") ? t.get("result").asText() : "");
                                tools.add(toolMap);
                            }
                            stepMap.put("tools", tools);
                        }
                        steps.add(stepMap);
                    }
                } catch (Exception ignored) {}
            }

            if (answer == null || answer.isBlank()) {
                answer = extractFinalAnswer(otherOutput.toString());
            }

            response.put("answer", stripEmoji(answer));
            response.put("steps",  steps);
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            response.put("answer", "Failed to reach agent: " + e.getMessage());
            response.put("steps",  Collections.emptyList());
            return ResponseEntity.internalServerError().body(response);
        }
    }

    private String extractFinalAnswer(String output) {
        if (output == null || output.isBlank()) return "Agent returned no output.";
        if (output.contains("FINAL ANALYSIS:")) {
            String after = output.substring(output.lastIndexOf("FINAL ANALYSIS:") + 15).trim();
            after = after.replaceAll("={3,}.*", "").trim();
            if (!after.isBlank()) return after;
        }
        if (output.contains("FINAL ANSWER:")) {
            String after = output.substring(output.lastIndexOf("FINAL ANSWER:") + 13).trim();
            after = after.replaceAll("={3,}.*", "").trim();
            if (!after.isBlank()) return after;
        }
        String[] lines = output.split("\n");
        for (int i = lines.length - 1; i >= 0; i--) {
            String l = lines[i].trim();
            if (!l.isEmpty() && !l.startsWith("=") && !l.startsWith("-")
                    && !l.startsWith("You:") && !l.startsWith("Goodbye")) {
                return l;
            }
        }
        return "Agent completed but produced no readable answer.";
    }

    private String stripEmoji(String text) {
        if (text == null) return "";
        return text.replaceAll("[\\uD800-\\uDFFF]", "")
                .replaceAll("[\\u2600-\\u27FF]", "")
                .replaceAll("\\s{2,}", " ").trim();
    }
}