{{- define "tep.name" -}}
{{- .Chart.Name -}}
{{- end -}}

{{- define "tep.labels" -}}
app.kubernetes.io/name: {{ include "tep.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "tep.image" -}}
{{ .Values.image.registry }}/{{ .component }}:{{ .Values.image.tag }}
{{- end -}}

{{/* Environment shared by the Java services */}}
{{- define "tep.commonEnv" -}}
- name: KAFKA_BOOTSTRAP_SERVERS
  value: {{ .Values.kafka.bootstrapServers | quote }}
- name: POSTGRES_URL
  value: {{ .Values.postgres.url | quote }}
- name: POSTGRES_USER
  value: {{ .Values.postgres.user | quote }}
- name: POSTGRES_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.postgres.existingSecret }}
      key: password
- name: OPENSEARCH_URL
  value: {{ .Values.opensearch.url | quote }}
- name: SERVER_PORT
  value: "8080"
- name: JAVA_TOOL_OPTIONS
  value: "-XX:MaxRAMPercentage=70 -XX:+UseG1GC"
{{- end -}}

{{/* One Deployment + Service for a Java service. Expects a dict with root, name, cfg, extraEnv (list), volumes, volumeMounts */}}
{{- define "tep.javaService" -}}
{{- $root := .root -}}
{{- $name := .name -}}
{{- $cfg := .cfg -}}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ $root.Release.Name }}-{{ $name }}
  labels:
    {{- include "tep.labels" $root | nindent 4 }}
    app.kubernetes.io/component: {{ $name }}
spec:
  replicas: {{ $cfg.replicas }}
  strategy:
    type: RollingUpdate
    rollingUpdate: { maxUnavailable: 0, maxSurge: 1 }
  selector:
    matchLabels:
      app.kubernetes.io/instance: {{ $root.Release.Name }}
      app.kubernetes.io/component: {{ $name }}
  template:
    metadata:
      labels:
        {{- include "tep.labels" $root | nindent 8 }}
        app.kubernetes.io/component: {{ $name }}
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/path: /actuator/prometheus
        prometheus.io/port: "8080"
    spec:
      securityContext:
        {{- toYaml $root.Values.podSecurityContext | nindent 8 }}
      terminationGracePeriodSeconds: 40
      containers:
        - name: {{ $name }}
          image: {{ include "tep.image" (dict "Values" $root.Values "component" $name) }}
          imagePullPolicy: {{ $root.Values.image.pullPolicy }}
          ports:
            - name: http
              containerPort: 8080
          env:
            {{- include "tep.commonEnv" $root | nindent 12 }}
            {{- with .extraEnv }}
            {{- toYaml . | nindent 12 }}
            {{- end }}
          readinessProbe:
            httpGet: { path: /actuator/health/readiness, port: http }
            initialDelaySeconds: 20
            periodSeconds: 10
          livenessProbe:
            httpGet: { path: /actuator/health/liveness, port: http }
            initialDelaySeconds: 60
            periodSeconds: 15
          resources:
            {{- toYaml $cfg.resources | nindent 12 }}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: { drop: [ALL] }
          volumeMounts:
            - name: tmp
              mountPath: /tmp
            {{- with .volumeMounts }}
            {{- toYaml . | nindent 12 }}
            {{- end }}
      volumes:
        - name: tmp
          emptyDir: {}
        {{- with .volumes }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
---
apiVersion: v1
kind: Service
metadata:
  name: {{ $root.Release.Name }}-{{ $name }}
  labels:
    {{- include "tep.labels" $root | nindent 4 }}
    app.kubernetes.io/component: {{ $name }}
spec:
  selector:
    app.kubernetes.io/instance: {{ $root.Release.Name }}
    app.kubernetes.io/component: {{ $name }}
  ports:
    - name: http
      port: 8080
      targetPort: http
{{- end -}}
