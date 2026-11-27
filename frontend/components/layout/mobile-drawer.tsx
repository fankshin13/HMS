"use client";

import { Menu, X } from "lucide-react";
import { useRef } from "react";
import { Brand, WorkspaceBadge } from "./brand";
import { NavList } from "./nav-list";

const iconButton =
  "inline-flex size-11 items-center justify-center rounded-md text-foreground hover:bg-card";

export function MobileDrawer() {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const close = () => dialogRef.current?.close();

  return (
    <>
      <button
        type="button"
        className={`${iconButton} lg:hidden`}
        aria-label="메뉴 열기"
        aria-haspopup="dialog"
        onClick={() => dialogRef.current?.showModal()}
      >
        <Menu aria-hidden="true" className="size-5" />
      </button>
      <dialog
        ref={dialogRef}
        aria-label="주 메뉴"
        className="nav-drawer m-0 h-dvh max-h-none w-72 max-w-[85vw] border-r border-border bg-background p-3 text-foreground"
        onClick={(event) => {
          // 백드롭(대화상자 바깥 영역) 클릭 시 닫기
          if (event.target === event.currentTarget) close();
        }}
      >
        <div className="flex h-full flex-col gap-4">
          <div className="flex items-center justify-between">
            <Brand />
            <button
              type="button"
              className={iconButton}
              aria-label="메뉴 닫기"
              onClick={close}
            >
              <X aria-hidden="true" className="size-5" />
            </button>
          </div>
          <WorkspaceBadge />
          <NavList onNavigate={close} />
        </div>
      </dialog>
    </>
  );
}
