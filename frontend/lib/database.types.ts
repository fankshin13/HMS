export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[];

export type Database = {
  public: {
    Tables: {
      assessment_runs: {
        Row: {
          completed_at: string | null;
          created_at: string;
          id: string;
          raw_archive_sha256: string | null;
          started_at: string | null;
          status: Database["public"]["Enums"]["assessment_status"];
          tenant_id: string;
          title: string;
          total_assets: number;
          updated_at: string;
          vulnerable_items_count: number;
        };
        ComputedFields: never;
        Insert: {
          completed_at?: string | null;
          created_at?: string;
          id?: string;
          raw_archive_sha256?: string | null;
          started_at?: string | null;
          status?: Database["public"]["Enums"]["assessment_status"];
          tenant_id: string;
          title: string;
          total_assets?: number;
          updated_at?: string;
          vulnerable_items_count?: number;
        };
        Update: {
          completed_at?: string | null;
          created_at?: string;
          id?: string;
          raw_archive_sha256?: string | null;
          started_at?: string | null;
          status?: Database["public"]["Enums"]["assessment_status"];
          tenant_id?: string;
          title?: string;
          total_assets?: number;
          updated_at?: string;
          vulnerable_items_count?: number;
        };
        Relationships: [
          {
            foreignKeyName: "assessment_runs_tenant_id_fkey";
            columns: ["tenant_id"];
            isOneToOne: false;
            referencedRelation: "tenants";
            referencedColumns: ["id"];
          },
        ];
      };
      assets: {
        Row: {
          availability_score: number;
          confidentiality_score: number;
          created_at: string;
          hostname: string;
          id: string;
          integrity_score: number;
          ip_address: string | null;
          last_assessed_at: string | null;
          os_type: Database["public"]["Enums"]["os_family"];
          os_version: string | null;
          tenant_id: string;
          updated_at: string;
        };
        ComputedFields: never;
        Insert: {
          availability_score?: number;
          confidentiality_score?: number;
          created_at?: string;
          hostname: string;
          id?: string;
          integrity_score?: number;
          ip_address?: string | null;
          last_assessed_at?: string | null;
          os_type: Database["public"]["Enums"]["os_family"];
          os_version?: string | null;
          tenant_id: string;
          updated_at?: string;
        };
        Update: {
          availability_score?: number;
          confidentiality_score?: number;
          created_at?: string;
          hostname?: string;
          id?: string;
          integrity_score?: number;
          ip_address?: string | null;
          last_assessed_at?: string | null;
          os_type?: Database["public"]["Enums"]["os_family"];
          os_version?: string | null;
          tenant_id?: string;
          updated_at?: string;
        };
        Relationships: [
          {
            foreignKeyName: "assets_tenant_id_fkey";
            columns: ["tenant_id"];
            isOneToOne: false;
            referencedRelation: "tenants";
            referencedColumns: ["id"];
          },
        ];
      };
      compliance_guidelines: {
        Row: {
          category: Database["public"]["Enums"]["compliance_category"];
          created_at: string;
          good_condition: string;
          item_code: string;
          name: string;
          remediation_guide: string;
          risk_level: Database["public"]["Enums"]["compliance_risk_level"];
          standard_criteria: string;
          updated_at: string;
          vulnerable_condition: string;
        };
        ComputedFields: never;
        Insert: {
          category: Database["public"]["Enums"]["compliance_category"];
          created_at?: string;
          good_condition: string;
          item_code: string;
          name: string;
          remediation_guide: string;
          risk_level: Database["public"]["Enums"]["compliance_risk_level"];
          standard_criteria: string;
          updated_at?: string;
          vulnerable_condition: string;
        };
        Update: {
          category?: Database["public"]["Enums"]["compliance_category"];
          created_at?: string;
          good_condition?: string;
          item_code?: string;
          name?: string;
          remediation_guide?: string;
          risk_level?: Database["public"]["Enums"]["compliance_risk_level"];
          standard_criteria?: string;
          updated_at?: string;
          vulnerable_condition?: string;
        };
        Relationships: [];
      };
      diagnostic_logs: {
        Row: {
          assessment_run_id: string;
          asset_id: string | null;
          created_at: string;
          error_details: Json | null;
          file_name: string;
          file_size_bytes: number;
          id: string;
          parse_status: Database["public"]["Enums"]["parsing_status"];
          quarantined_error_lines: number;
          storage_path: string | null;
          tenant_id: string;
        };
        ComputedFields: never;
        Insert: {
          assessment_run_id: string;
          asset_id?: string | null;
          created_at?: string;
          error_details?: Json | null;
          file_name: string;
          file_size_bytes: number;
          id?: string;
          parse_status?: Database["public"]["Enums"]["parsing_status"];
          quarantined_error_lines?: number;
          storage_path?: string | null;
          tenant_id: string;
        };
        Update: {
          assessment_run_id?: string;
          asset_id?: string | null;
          created_at?: string;
          error_details?: Json | null;
          file_name?: string;
          file_size_bytes?: number;
          id?: string;
          parse_status?: Database["public"]["Enums"]["parsing_status"];
          quarantined_error_lines?: number;
          storage_path?: string | null;
          tenant_id?: string;
        };
        Relationships: [
          {
            foreignKeyName: "diagnostic_logs_asset_fk";
            columns: ["asset_id", "tenant_id"];
            isOneToOne: false;
            referencedRelation: "assets";
            referencedColumns: ["id", "tenant_id"];
          },
          {
            foreignKeyName: "diagnostic_logs_run_fk";
            columns: ["assessment_run_id", "tenant_id"];
            isOneToOne: false;
            referencedRelation: "assessment_runs";
            referencedColumns: ["id", "tenant_id"];
          },
          {
            foreignKeyName: "diagnostic_logs_tenant_id_fkey";
            columns: ["tenant_id"];
            isOneToOne: false;
            referencedRelation: "tenants";
            referencedColumns: ["id"];
          },
        ];
      };
      generated_reports: {
        Row: {
          assessment_run_id: string;
          created_at: string;
          expires_at: string;
          file_size_bytes: number;
          format: Database["public"]["Enums"]["report_format"];
          id: string;
          report_type: Database["public"]["Enums"]["report_type"];
          storage_path: string;
          tenant_id: string;
        };
        ComputedFields: never;
        Insert: {
          assessment_run_id: string;
          created_at?: string;
          expires_at: string;
          file_size_bytes: number;
          format: Database["public"]["Enums"]["report_format"];
          id?: string;
          report_type: Database["public"]["Enums"]["report_type"];
          storage_path: string;
          tenant_id: string;
        };
        Update: {
          assessment_run_id?: string;
          created_at?: string;
          expires_at?: string;
          file_size_bytes?: number;
          format?: Database["public"]["Enums"]["report_format"];
          id?: string;
          report_type?: Database["public"]["Enums"]["report_type"];
          storage_path?: string;
          tenant_id?: string;
        };
        Relationships: [
          {
            foreignKeyName: "generated_reports_tenant_id_fkey";
            columns: ["tenant_id"];
            isOneToOne: false;
            referencedRelation: "tenants";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "reports_run_fk";
            columns: ["assessment_run_id", "tenant_id"];
            isOneToOne: false;
            referencedRelation: "assessment_runs";
            referencedColumns: ["id", "tenant_id"];
          },
        ];
      };
      inspection_item_results: {
        Row: {
          assessment_run_id: string;
          asset_id: string;
          auto_status: Database["public"]["Enums"]["item_status"];
          calculated_risk_score: number;
          created_at: string;
          final_status: Database["public"]["Enums"]["item_status"];
          id: string;
          item_code: string;
          raw_log_end_line: number | null;
          raw_log_start_line: number | null;
          stdout_snippet: string | null;
          tenant_id: string;
          updated_at: string;
        };
        ComputedFields: never;
        Insert: {
          assessment_run_id: string;
          asset_id: string;
          auto_status: Database["public"]["Enums"]["item_status"];
          calculated_risk_score?: number;
          created_at?: string;
          final_status: Database["public"]["Enums"]["item_status"];
          id?: string;
          item_code: string;
          raw_log_end_line?: number | null;
          raw_log_start_line?: number | null;
          stdout_snippet?: string | null;
          tenant_id: string;
          updated_at?: string;
        };
        Update: {
          assessment_run_id?: string;
          asset_id?: string;
          auto_status?: Database["public"]["Enums"]["item_status"];
          calculated_risk_score?: number;
          created_at?: string;
          final_status?: Database["public"]["Enums"]["item_status"];
          id?: string;
          item_code?: string;
          raw_log_end_line?: number | null;
          raw_log_start_line?: number | null;
          stdout_snippet?: string | null;
          tenant_id?: string;
          updated_at?: string;
        };
        Relationships: [
          {
            foreignKeyName: "inspection_item_results_item_code_fkey";
            columns: ["item_code"];
            isOneToOne: false;
            referencedRelation: "compliance_guidelines";
            referencedColumns: ["item_code"];
          },
          {
            foreignKeyName: "inspection_item_results_tenant_id_fkey";
            columns: ["tenant_id"];
            isOneToOne: false;
            referencedRelation: "tenants";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "results_asset_fk";
            columns: ["asset_id", "tenant_id"];
            isOneToOne: false;
            referencedRelation: "assets";
            referencedColumns: ["id", "tenant_id"];
          },
          {
            foreignKeyName: "results_run_fk";
            columns: ["assessment_run_id", "tenant_id"];
            isOneToOne: false;
            referencedRelation: "assessment_runs";
            referencedColumns: ["id", "tenant_id"];
          },
        ];
      };
      invitations: {
        Row: {
          created_at: string;
          expires_at: string;
          id: string;
          tenant_id: string;
          token_hash: string;
          used_at: string | null;
          user_id: string;
        };
        ComputedFields: never;
        Insert: {
          created_at?: string;
          expires_at: string;
          id?: string;
          tenant_id: string;
          token_hash: string;
          used_at?: string | null;
          user_id: string;
        };
        Update: {
          created_at?: string;
          expires_at?: string;
          id?: string;
          tenant_id?: string;
          token_hash?: string;
          used_at?: string | null;
          user_id?: string;
        };
        Relationships: [
          {
            foreignKeyName: "invitations_tenant_id_fkey";
            columns: ["tenant_id"];
            isOneToOne: false;
            referencedRelation: "tenants";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "invitations_user_fk";
            columns: ["user_id", "tenant_id"];
            isOneToOne: false;
            referencedRelation: "users";
            referencedColumns: ["id", "tenant_id"];
          },
        ];
      };
      override_audit_logs: {
        Row: {
          actor_user_id: string;
          created_at: string;
          id: string;
          inspection_item_result_id: string;
          new_status: Database["public"]["Enums"]["item_status"];
          override_reason: string;
          previous_status: Database["public"]["Enums"]["item_status"];
          tenant_id: string;
        };
        ComputedFields: never;
        Insert: {
          actor_user_id: string;
          created_at?: string;
          id?: string;
          inspection_item_result_id: string;
          new_status: Database["public"]["Enums"]["item_status"];
          override_reason: string;
          previous_status: Database["public"]["Enums"]["item_status"];
          tenant_id: string;
        };
        Update: {
          actor_user_id?: string;
          created_at?: string;
          id?: string;
          inspection_item_result_id?: string;
          new_status?: Database["public"]["Enums"]["item_status"];
          override_reason?: string;
          previous_status?: Database["public"]["Enums"]["item_status"];
          tenant_id?: string;
        };
        Relationships: [
          {
            foreignKeyName: "audit_actor_fk";
            columns: ["actor_user_id", "tenant_id"];
            isOneToOne: false;
            referencedRelation: "users";
            referencedColumns: ["id", "tenant_id"];
          },
          {
            foreignKeyName: "audit_result_fk";
            columns: ["inspection_item_result_id", "tenant_id"];
            isOneToOne: false;
            referencedRelation: "inspection_item_results";
            referencedColumns: ["id", "tenant_id"];
          },
          {
            foreignKeyName: "override_audit_logs_tenant_id_fkey";
            columns: ["tenant_id"];
            isOneToOne: false;
            referencedRelation: "tenants";
            referencedColumns: ["id"];
          },
        ];
      };
      risk_scoring_policies: {
        Row: {
          availability_weight: number;
          confidentiality_weight: number;
          created_at: string;
          critical_threshold: number;
          id: string;
          integrity_weight: number;
          tenant_id: string;
          updated_at: string;
          warning_threshold: number;
        };
        ComputedFields: never;
        Insert: {
          availability_weight?: number;
          confidentiality_weight?: number;
          created_at?: string;
          critical_threshold?: number;
          id?: string;
          integrity_weight?: number;
          tenant_id: string;
          updated_at?: string;
          warning_threshold?: number;
        };
        Update: {
          availability_weight?: number;
          confidentiality_weight?: number;
          created_at?: string;
          critical_threshold?: number;
          id?: string;
          integrity_weight?: number;
          tenant_id?: string;
          updated_at?: string;
          warning_threshold?: number;
        };
        Relationships: [
          {
            foreignKeyName: "risk_scoring_policies_tenant_id_fkey";
            columns: ["tenant_id"];
            isOneToOne: true;
            referencedRelation: "tenants";
            referencedColumns: ["id"];
          },
        ];
      };
      tenants: {
        Row: {
          created_at: string;
          id: string;
          name: string;
          updated_at: string;
          zero_retention_enabled: boolean;
        };
        ComputedFields: never;
        Insert: {
          created_at?: string;
          id?: string;
          name: string;
          updated_at?: string;
          zero_retention_enabled?: boolean;
        };
        Update: {
          created_at?: string;
          id?: string;
          name?: string;
          updated_at?: string;
          zero_retention_enabled?: boolean;
        };
        Relationships: [];
      };
      users: {
        Row: {
          auth_user_id: string | null;
          created_at: string;
          email: string;
          id: string;
          name: string;
          role: Database["public"]["Enums"]["user_role"];
          status: Database["public"]["Enums"]["user_status"];
          tenant_id: string;
          updated_at: string;
        };
        ComputedFields: never;
        Insert: {
          auth_user_id?: string | null;
          created_at?: string;
          email: string;
          id?: string;
          name: string;
          role?: Database["public"]["Enums"]["user_role"];
          status?: Database["public"]["Enums"]["user_status"];
          tenant_id: string;
          updated_at?: string;
        };
        Update: {
          auth_user_id?: string | null;
          created_at?: string;
          email?: string;
          id?: string;
          name?: string;
          role?: Database["public"]["Enums"]["user_role"];
          status?: Database["public"]["Enums"]["user_status"];
          tenant_id?: string;
          updated_at?: string;
        };
        Relationships: [
          {
            foreignKeyName: "users_tenant_id_fkey";
            columns: ["tenant_id"];
            isOneToOne: false;
            referencedRelation: "tenants";
            referencedColumns: ["id"];
          },
        ];
      };
    };
    Views: {
      [_ in never]: never;
    };
    Functions: {
      accept_invitation: {
        Args: { p_token_hash: string };
        Returns: {
          status: string;
          tenant_id: string;
        }[];
      };
      apply_item_override: {
        Args: {
          p_item_result_id: string;
          p_new_status: Database["public"]["Enums"]["item_status"];
          p_reason: string;
        };
        Returns: undefined;
      };
      create_invitation: {
        Args: {
          p_email: string;
          p_name: string;
          p_role: Database["public"]["Enums"]["user_role"];
          p_tenant_id: string;
          p_token_hash: string;
          p_valid_hours: number;
        };
        Returns: {
          expires_at: string;
          invitation_id: string;
        }[];
      };
      inspect_invitation: {
        Args: { p_token_hash: string };
        Returns: {
          email: string;
          role: Database["public"]["Enums"]["user_role"];
          status: string;
          tenant_name: string;
          user_name: string;
        }[];
      };
      register_assessment_upload: {
        Args: {
          p_allow_duplicate?: boolean;
          p_logs: Json;
          p_run_id: string;
          p_sha256: string;
          p_tenant_id: string;
          p_title: string;
        };
        Returns: Json;
      };
      revoke_invitation: {
        Args: { p_invitation_id: string };
        Returns: undefined;
      };
    };
    Enums: {
      assessment_status:
        "queued" | "parsing" | "scoring" | "rendering" | "completed" | "failed";
      compliance_category:
        | "account_management"
        | "directory_file_management"
        | "service_management"
        | "patch_management"
        | "log_management";
      compliance_risk_level: "high" | "medium" | "low";
      item_status: "good" | "vulnerable" | "na";
      os_family: "linux" | "windows";
      parsing_status: "success" | "partial_error" | "failed";
      report_format: "docx" | "pdf";
      report_type: "detailed" | "summary" | "risk_plan";
      user_role: "owner" | "operator" | "viewer";
      user_status: "active" | "invited" | "suspended";
    };
    CompositeTypes: {
      [_ in never]: never;
    };
  };
};

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">;

type DefaultSchema = DatabaseWithoutInternals[Extract<
  keyof Database,
  "public"
>];

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals;
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals;
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R;
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R;
      }
      ? R
      : never
    : never;

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    keyof DefaultSchema["Tables"] | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals;
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals;
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I;
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I;
      }
      ? I
      : never
    : never;

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    keyof DefaultSchema["Tables"] | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals;
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals;
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U;
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U;
      }
      ? U
      : never
    : never;

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    keyof DefaultSchema["Enums"] | { schema: keyof DatabaseWithoutInternals },
  EnumName extends (DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals;
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never) = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals;
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never;

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends (PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals;
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never) = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals;
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never;

export const Constants = {
  public: {
    Enums: {
      assessment_status: [
        "queued",
        "parsing",
        "scoring",
        "rendering",
        "completed",
        "failed",
      ],
      compliance_category: [
        "account_management",
        "directory_file_management",
        "service_management",
        "patch_management",
        "log_management",
      ],
      compliance_risk_level: ["high", "medium", "low"],
      item_status: ["good", "vulnerable", "na"],
      os_family: ["linux", "windows"],
      parsing_status: ["success", "partial_error", "failed"],
      report_format: ["docx", "pdf"],
      report_type: ["detailed", "summary", "risk_plan"],
      user_role: ["owner", "operator", "viewer"],
      user_status: ["active", "invited", "suspended"],
    },
  },
} as const;
