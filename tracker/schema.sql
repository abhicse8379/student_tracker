-- Run this once in Supabase: SQL Editor > New query > paste > Run

create table profiles (
  id uuid primary key references auth.users on delete cascade,
  full_name text, email text,
  role text not null default 'student' check (role in ('student','admin')),
  interest text check (interest in ('project','research')),
  status text not null default 'pending' check (status in ('pending','approved')),
  created_at timestamptz default now()
);
create table works (
  id uuid primary key default gen_random_uuid(),
  kind text not null check (kind in ('project','research')),
  title text not null, description text,
  start_date date default current_date, deadline date,
  status text not null default 'active' check (status in ('active','on_hold','completed')),
  outcome_type text, outcome_link text, outcome_notes text,
  created_at timestamptz default now()
);
create table work_members (
  work_id uuid references works on delete cascade,
  student_id uuid references profiles on delete cascade,
  primary key (work_id, student_id)
);
create table tasks (
  id uuid primary key default gen_random_uuid(),
  work_id uuid not null references works on delete cascade,
  title text not null, description text, due_date date,
  status text not null default 'not_started' check (status in ('not_started','in_progress','submitted','reviewed')),
  submission_link text, feedback text,
  created_at timestamptz default now()
);
create table meetings (
  id uuid primary key default gen_random_uuid(),
  work_id uuid not null references works on delete cascade,
  meeting_date date not null default current_date,
  notes text, action_items text, next_meeting date,
  created_at timestamptz default now()
);

-- Helpers (security definer avoids recursive policy checks)
create function is_admin() returns boolean language sql security definer stable set search_path = public as
$$ select exists(select 1 from profiles where id = auth.uid() and role = 'admin' and status = 'approved') $$;
create function is_member(w uuid) returns boolean language sql security definer stable set search_path = public as
$$ select exists(select 1 from work_members m join profiles p on p.id = m.student_id
   where m.work_id = w and m.student_id = auth.uid() and p.status = 'approved') $$;

-- Auto-create a profile on signup. Role is ALWAYS student here.
create function handle_new_user() returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into profiles(id, email, full_name, interest)
  values (new.id, new.email, new.raw_user_meta_data->>'full_name',
          case when new.raw_user_meta_data->>'interest' in ('project','research')
               then new.raw_user_meta_data->>'interest' end);
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users for each row execute function handle_new_user();

-- Students may only change status + submission_link on a task
create function guard_task_update() returns trigger language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() and (new.title, new.description, new.due_date, new.work_id, new.feedback)
     is distinct from (old.title, old.description, old.due_date, old.work_id, old.feedback) then
    raise exception 'Students can only update status and submission link';
  end if;
  return new;
end $$;
create trigger task_guard before update on tasks for each row execute function guard_task_update();

alter table profiles enable row level security;
alter table works enable row level security;
alter table work_members enable row level security;
alter table tasks enable row level security;
alter table meetings enable row level security;

create policy p_sel on profiles for select using (id = auth.uid() or is_admin());
create policy p_adm on profiles for all using (is_admin()) with check (is_admin());

create policy w_sel on works for select using (is_member(id));
create policy w_adm on works for all using (is_admin()) with check (is_admin());

create policy m_sel on work_members for select using (student_id = auth.uid() or is_admin());
create policy m_adm on work_members for all using (is_admin()) with check (is_admin());

create policy t_sel on tasks for select using (is_member(work_id));
create policy t_upd on tasks for update using (is_member(work_id)) with check (is_member(work_id));
create policy t_adm on tasks for all using (is_admin()) with check (is_admin());

create policy mt_sel on meetings for select using (is_member(work_id));
create policy mt_adm on meetings for all using (is_admin()) with check (is_admin());

-- AFTER you sign up once through the app, make yourself admin (change the email):
-- update profiles set role = 'admin', status = 'approved' where email = 'you@example.com';
