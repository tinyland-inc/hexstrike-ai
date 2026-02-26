# HexStrike-AI Kubernetes deployment via OpenTofu.
# State backend: GitLab HTTP state

terraform {
  required_version = ">= 1.6"

  backend "http" {
    # Configured via environment variables:
    # TF_HTTP_ADDRESS, TF_HTTP_LOCK_ADDRESS, TF_HTTP_UNLOCK_ADDRESS
  }

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.27"
    }
  }
}

provider "kubernetes" {
  # Uses KUBECONFIG or in-cluster config
}

variable "namespace" {
  type    = string
  default = "fuzzy-dev"
}

variable "image" {
  type    = string
  default = "ghcr.io/tinyland-inc/hexstrike-ai:edge"
}

variable "replicas" {
  type    = number
  default = 1
}

resource "kubernetes_deployment" "hexstrike" {
  metadata {
    name      = "hexstrike-ai"
    namespace = var.namespace
    labels = {
      app = "hexstrike-ai"
    }
  }

  spec {
    replicas = var.replicas

    selector {
      match_labels = {
        app = "hexstrike-ai"
      }
    }

    template {
      metadata {
        labels = {
          app = "hexstrike-ai"
        }
        annotations = {
          "prometheus.io/scrape" = "true"
          "prometheus.io/port"   = "9090"
          "prometheus.io/path"   = "/metrics"
        }
      }

      spec {
        container {
          name  = "gateway"
          image = var.image

          port {
            container_port = 8080
            name           = "http"
          }

          port {
            container_port = 9090
            name           = "metrics"
          }

          env {
            name  = "HEXSTRIKE_RESULTS_DIR"
            value = "/results"
          }

          volume_mount {
            name       = "results"
            mount_path = "/results"
          }

          liveness_probe {
            http_get {
              path = "/health"
              port = 8080
            }
            initial_delay_seconds = 10
            period_seconds        = 30
          }

          readiness_probe {
            http_get {
              path = "/health"
              port = 8080
            }
            initial_delay_seconds = 5
            period_seconds        = 10
          }

          resources {
            requests = {
              cpu    = "100m"
              memory = "128Mi"
            }
            limits = {
              cpu    = "500m"
              memory = "512Mi"
            }
          }
        }

        volume {
          name = "results"
          empty_dir {}
        }
      }
    }
  }
}

resource "kubernetes_service" "hexstrike" {
  metadata {
    name      = "hexstrike-ai"
    namespace = var.namespace
  }

  spec {
    selector = {
      app = "hexstrike-ai"
    }

    port {
      name        = "http"
      port        = 8080
      target_port = 8080
    }

    port {
      name        = "metrics"
      port        = 9090
      target_port = 9090
    }
  }
}

resource "kubernetes_horizontal_pod_autoscaler_v2" "hexstrike" {
  metadata {
    name      = "hexstrike-ai"
    namespace = var.namespace
  }

  spec {
    scale_target_ref {
      api_version = "apps/v1"
      kind        = "Deployment"
      name        = kubernetes_deployment.hexstrike.metadata[0].name
    }

    min_replicas = 1
    max_replicas = 5

    metric {
      type = "Resource"
      resource {
        name = "cpu"
        target {
          type                = "Utilization"
          average_utilization = 70
        }
      }
    }
  }
}

resource "kubernetes_pod_disruption_budget_v1" "hexstrike" {
  metadata {
    name      = "hexstrike-ai"
    namespace = var.namespace
  }

  spec {
    min_available = 1

    selector {
      match_labels = {
        app = "hexstrike-ai"
      }
    }
  }
}
