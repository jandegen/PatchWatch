{{- define "patchwatch.labels" -}}
app.kubernetes.io/part-of: patchwatch
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
{{- define "patchwatch.pullSecrets" -}}
{{- if .Values.imagePullSecrets }}
imagePullSecrets:
{{- range .Values.imagePullSecrets }}
  - name: {{ . }}
{{- end }}
{{- end }}
{{- end }}
