 resource "github_repository" "this" {
      name         = var.name
      description  = var.description
      homepage_url = var.homepage_url
   
      archived   = true
      visibility = "public"
   
      has_downloads = var.has_downloads
      has_issues    = var.has_issues
      has_projects  = var.has_projects
      has_wiki      = var.has_wiki
   
      delete_branch_on_merge = var.delete_branch_on_merge
      vulnerability_alerts   = var.vulnerability_alerts
   
      topics = var.topics
   
      dynamic "pages" {
        for_each = range(var.has_github_pages ? 1 : 0)
   
        content {
          cname = var.github_pages_cname
   
          source {
            branch = "gh-pages"
            path   = "/"
          }
        }
      }
   
      lifecycle {
        prevent_destroy = true
      }
    }