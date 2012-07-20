(*
 * Copyright (C) 2006-2007 XenSource Ltd.
 * Copyright (C) 2008      Citrix Ltd.
 * Author Vincent Hanquez <vincent.hanquez@eu.citrix.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *)

type domains = {
	eventchn: Event.t;
	table: (Xc.domid, Domain.t) Hashtbl.t;
}

let init eventchn =
	{ eventchn = eventchn; table = Hashtbl.create 10 }
let del doms id = Hashtbl.remove doms.table id
let exist doms id = Hashtbl.mem doms.table id
let find doms id = Hashtbl.find doms.table id
let number doms = Hashtbl.length doms.table
let iter doms fct = Hashtbl.iter (fun _ b -> fct b) doms.table

let cleanup xc doms =
	let notify = ref false in
	let dead_dom = ref [] in

	Hashtbl.iter (fun id _ -> if id <> 0 then
		try
			let info = Xc.domain_getinfo xc id in
			if info.Xc.shutdown || info.Xc.dying then (
				Logs.debug "general" "Domain %u died (dying=%b, shutdown %b -- code %d)"
				                    id info.Xc.dying info.Xc.shutdown info.Xc.shutdown_code;
				if info.Xc.dying then
					dead_dom := id :: !dead_dom
				else
					notify := true;
			)
		with Xc.Error _ ->
			Logs.debug "general" "Domain %u died -- no domain info" id;
			dead_dom := id :: !dead_dom;
		) doms.table;
	List.iter (fun id ->
		let dom = Hashtbl.find doms.table id in
		Domain.close dom;
		Hashtbl.remove doms.table id;
	) !dead_dom;
	!notify, !dead_dom

let resume doms domid =
	()

let create xc doms domid mfn port =
	let interface = Xc.map_foreign_range xc domid (Mmap.getpagesize()) mfn in
	let dom = Domain.make domid mfn port interface doms.eventchn in
	Hashtbl.add doms.table domid dom;
	Domain.bind_interdomain dom;
	dom

let create0 fake doms =
	let port, interface =
		if fake then (
			0, Xc.with_intf (fun xc -> Xc.map_foreign_range xc 0 (Mmap.getpagesize()) 0n)
		) else (
			let port = Utils.read_file_single_integer Define.xenstored_proc_port
			and fd = Unix.openfile Define.xenstored_proc_kva
					       [ Unix.O_RDWR ] 0o600 in
			let interface = Mmap.mmap fd Mmap.RDWR Mmap.SHARED
						  (Mmap.getpagesize()) 0 in
			Unix.close fd;
			port, interface
		)
		in
	let dom = Domain.make 0 Nativeint.zero port interface doms.eventchn in
	Hashtbl.add doms.table 0 dom;
	Domain.bind_interdomain dom;
	Domain.notify dom;
	dom
