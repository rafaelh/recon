// Package risk has the risk stages: email (DNS posture of the input roots),
// storage (cloud buckets), takeover (unclaimed provider resources) and
// sensitive-paths (exposed files). They store evidence only; the findings
// package derives the findings from it. Like every stage it never touches the
// network itself: all I/O goes through egress.
package risk
