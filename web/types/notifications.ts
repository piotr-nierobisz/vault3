export type NotificationItem = {
  id: string;
  kind: string;
  title: string;
  body: string;
  isRead: boolean;
  timeLabel: string;
  href?: string;
  icon: string;
};

export type NotificationsPageData = {
  PageTitle: string;
  Notifications: NotificationItem[];
  UnreadCount: number;
};
