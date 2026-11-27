import {
  ClipboardList,
  FileCode,
  LayoutDashboard,
  type LucideIcon,
  Server,
  SlidersHorizontal,
  Users,
} from "lucide-react";

export type Role = "owner" | "operator" | "viewer";

export interface NavigationItem {
  title: string;
  href: string;
  icon: LucideIcon;
  roles: Role[];
  exact?: boolean;
}

export interface NavigationGroup {
  label: string;
  items: NavigationItem[];
}

// 역할(roles)은 마스터 스펙 라우트 맵 기준. 인증 태스크 전까지는 필터링하지 않고 모두 표시한다.
export const NAVIGATION: NavigationGroup[] = [
  {
    label: "진단",
    items: [
      {
        title: "대시보드",
        href: "/dashboard",
        icon: LayoutDashboard,
        roles: ["owner", "operator", "viewer"],
        exact: true,
      },
      {
        title: "진단 차수",
        href: "/assessments",
        icon: ClipboardList,
        roles: ["owner", "operator", "viewer"],
      },
      {
        title: "자산 목록",
        href: "/assets",
        icon: Server,
        roles: ["owner", "operator", "viewer"],
      },
      {
        title: "스크립트 센터",
        href: "/scripts",
        icon: FileCode,
        roles: ["owner", "operator"],
      },
    ],
  },
  {
    label: "설정",
    items: [
      {
        title: "위험도 정책",
        href: "/settings/risk-policy",
        icon: SlidersHorizontal,
        roles: ["owner"],
      },
      {
        title: "팀원 관리",
        href: "/settings/team",
        icon: Users,
        roles: ["owner"],
      },
    ],
  },
];

export function isActivePath(
  pathname: string,
  item: Pick<NavigationItem, "href" | "exact">,
) {
  if (item.exact) return pathname === item.href;
  return pathname === item.href || pathname.startsWith(`${item.href}/`);
}

export interface Breadcrumb {
  label: string;
  href?: string;
}

const SEGMENT_LABELS: Record<string, string> = {
  dashboard: "대시보드",
  assets: "자산 목록",
  scripts: "스크립트 센터",
  assessments: "진단 차수",
  new: "신규 진단",
  items: "점검 항목",
  reports: "보고서",
  settings: "설정",
  "risk-policy": "위험도 정책",
  team: "팀원 관리",
};

// 하위 페이지가 없는 경로 구간은 링크하지 않는다.
const UNLINKED_PATHS = new Set(["/settings"]);

export function getBreadcrumbs(pathname: string): Breadcrumb[] {
  const segments = pathname.split("/").filter(Boolean);
  return segments.map((segment, index) => {
    const href = `/${segments.slice(0, index + 1).join("/")}`;
    const isAssessmentId =
      segments[0] === "assessments" && index === 1 && segment !== "new";
    const label = isAssessmentId
      ? `진단 ${decodeURIComponent(segment)}`
      : (SEGMENT_LABELS[segment] ?? decodeURIComponent(segment));
    const isLast = index === segments.length - 1;
    return {
      label,
      href: isLast || UNLINKED_PATHS.has(href) ? undefined : href,
    };
  });
}
