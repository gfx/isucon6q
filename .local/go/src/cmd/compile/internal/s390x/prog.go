// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package s390x

import (
	"cmd/compile/internal/gc"
	"cmd/internal/obj"
	"cmd/internal/obj/s390x"
)

// This table gives the basic information about instruction
// generated by the compiler and processed in the optimizer.
// See opt.h for bit definitions.
//
// Instructions not generated need not be listed.
// As an exception to that rule, we typically write down all the
// size variants of an operation even if we just use a subset.
var progtable = [s390x.ALAST & obj.AMask]obj.ProgInfo{
	obj.ATYPE & obj.AMask:     {Flags: gc.Pseudo | gc.Skip},
	obj.ATEXT & obj.AMask:     {Flags: gc.Pseudo},
	obj.AFUNCDATA & obj.AMask: {Flags: gc.Pseudo},
	obj.APCDATA & obj.AMask:   {Flags: gc.Pseudo},
	obj.AUNDEF & obj.AMask:    {Flags: gc.Break},
	obj.AUSEFIELD & obj.AMask: {Flags: gc.OK},
	obj.ACHECKNIL & obj.AMask: {Flags: gc.LeftRead},
	obj.AVARDEF & obj.AMask:   {Flags: gc.Pseudo | gc.RightWrite},
	obj.AVARKILL & obj.AMask:  {Flags: gc.Pseudo | gc.RightWrite},
	obj.AVARLIVE & obj.AMask:  {Flags: gc.Pseudo | gc.LeftRead},

	// NOP is an internal no-op that also stands
	// for USED and SET annotations.
	obj.ANOP & obj.AMask: {Flags: gc.LeftRead | gc.RightWrite},

	// Integer
	s390x.AADD & obj.AMask:    {Flags: gc.SizeQ | gc.LeftRead | gc.RegRead | gc.RightWrite},
	s390x.ASUB & obj.AMask:    {Flags: gc.SizeQ | gc.LeftRead | gc.RegRead | gc.RightWrite},
	s390x.ANEG & obj.AMask:    {Flags: gc.SizeQ | gc.LeftRead | gc.RegRead | gc.RightWrite},
	s390x.AAND & obj.AMask:    {Flags: gc.SizeQ | gc.LeftRead | gc.RegRead | gc.RightWrite},
	s390x.AOR & obj.AMask:     {Flags: gc.SizeQ | gc.LeftRead | gc.RegRead | gc.RightWrite},
	s390x.AXOR & obj.AMask:    {Flags: gc.SizeQ | gc.LeftRead | gc.RegRead | gc.RightWrite},
	s390x.AMULLD & obj.AMask:  {Flags: gc.SizeQ | gc.LeftRead | gc.RegRead | gc.RightWrite},
	s390x.AMULLW & obj.AMask:  {Flags: gc.SizeL | gc.LeftRead | gc.RegRead | gc.RightWrite},
	s390x.AMULHD & obj.AMask:  {Flags: gc.SizeL | gc.LeftRead | gc.RegRead | gc.RightWrite},
	s390x.AMULHDU & obj.AMask: {Flags: gc.SizeL | gc.LeftRead | gc.RegRead | gc.RightWrite},
	s390x.ADIVD & obj.AMask:   {Flags: gc.SizeQ | gc.LeftRead | gc.RegRead | gc.RightWrite},
	s390x.ADIVDU & obj.AMask:  {Flags: gc.SizeQ | gc.LeftRead | gc.RegRead | gc.RightWrite},
	s390x.ASLD & obj.AMask:    {Flags: gc.SizeQ | gc.LeftRead | gc.RegRead | gc.RightWrite},
	s390x.ASRD & obj.AMask:    {Flags: gc.SizeQ | gc.LeftRead | gc.RegRead | gc.RightWrite},
	s390x.ASRAD & obj.AMask:   {Flags: gc.SizeQ | gc.LeftRead | gc.RegRead | gc.RightWrite},
	s390x.ARLL & obj.AMask:    {Flags: gc.SizeL | gc.LeftRead | gc.RegRead | gc.RightWrite},
	s390x.ARLLG & obj.AMask:   {Flags: gc.SizeQ | gc.LeftRead | gc.RegRead | gc.RightWrite},
	s390x.ACMP & obj.AMask:    {Flags: gc.SizeQ | gc.LeftRead | gc.RightRead},
	s390x.ACMPU & obj.AMask:   {Flags: gc.SizeQ | gc.LeftRead | gc.RightRead},

	// Floating point.
	s390x.AFADD & obj.AMask:  {Flags: gc.SizeD | gc.LeftRead | gc.RegRead | gc.RightWrite},
	s390x.AFADDS & obj.AMask: {Flags: gc.SizeF | gc.LeftRead | gc.RegRead | gc.RightWrite},
	s390x.AFSUB & obj.AMask:  {Flags: gc.SizeD | gc.LeftRead | gc.RegRead | gc.RightWrite},
	s390x.AFSUBS & obj.AMask: {Flags: gc.SizeF | gc.LeftRead | gc.RegRead | gc.RightWrite},
	s390x.AFMUL & obj.AMask:  {Flags: gc.SizeD | gc.LeftRead | gc.RegRead | gc.RightWrite},
	s390x.AFMULS & obj.AMask: {Flags: gc.SizeF | gc.LeftRead | gc.RegRead | gc.RightWrite},
	s390x.AFDIV & obj.AMask:  {Flags: gc.SizeD | gc.LeftRead | gc.RegRead | gc.RightWrite},
	s390x.AFDIVS & obj.AMask: {Flags: gc.SizeF | gc.LeftRead | gc.RegRead | gc.RightWrite},
	s390x.AFCMPU & obj.AMask: {Flags: gc.SizeD | gc.LeftRead | gc.RightRead},
	s390x.ACEBR & obj.AMask:  {Flags: gc.SizeF | gc.LeftRead | gc.RightRead},
	s390x.ALEDBR & obj.AMask: {Flags: gc.SizeD | gc.LeftRead | gc.RightWrite | gc.Conv},
	s390x.ALDEBR & obj.AMask: {Flags: gc.SizeD | gc.LeftRead | gc.RightWrite | gc.Conv},
	s390x.AFSQRT & obj.AMask: {Flags: gc.SizeD | gc.LeftRead | gc.RightWrite},

	// Conversions
	s390x.ACEFBRA & obj.AMask: {Flags: gc.SizeF | gc.LeftRead | gc.RightWrite | gc.Conv},
	s390x.ACDFBRA & obj.AMask: {Flags: gc.SizeD | gc.LeftRead | gc.RightWrite | gc.Conv},
	s390x.ACEGBRA & obj.AMask: {Flags: gc.SizeF | gc.LeftRead | gc.RightWrite | gc.Conv},
	s390x.ACDGBRA & obj.AMask: {Flags: gc.SizeD | gc.LeftRead | gc.RightWrite | gc.Conv},
	s390x.ACFEBRA & obj.AMask: {Flags: gc.SizeL | gc.LeftRead | gc.RightWrite | gc.Conv},
	s390x.ACFDBRA & obj.AMask: {Flags: gc.SizeL | gc.LeftRead | gc.RightWrite | gc.Conv},
	s390x.ACGEBRA & obj.AMask: {Flags: gc.SizeQ | gc.LeftRead | gc.RightWrite | gc.Conv},
	s390x.ACGDBRA & obj.AMask: {Flags: gc.SizeQ | gc.LeftRead | gc.RightWrite | gc.Conv},
	s390x.ACELFBR & obj.AMask: {Flags: gc.SizeF | gc.LeftRead | gc.RightWrite | gc.Conv},
	s390x.ACDLFBR & obj.AMask: {Flags: gc.SizeD | gc.LeftRead | gc.RightWrite | gc.Conv},
	s390x.ACELGBR & obj.AMask: {Flags: gc.SizeF | gc.LeftRead | gc.RightWrite | gc.Conv},
	s390x.ACDLGBR & obj.AMask: {Flags: gc.SizeD | gc.LeftRead | gc.RightWrite | gc.Conv},
	s390x.ACLFEBR & obj.AMask: {Flags: gc.SizeL | gc.LeftRead | gc.RightWrite | gc.Conv},
	s390x.ACLFDBR & obj.AMask: {Flags: gc.SizeL | gc.LeftRead | gc.RightWrite | gc.Conv},
	s390x.ACLGEBR & obj.AMask: {Flags: gc.SizeQ | gc.LeftRead | gc.RightWrite | gc.Conv},
	s390x.ACLGDBR & obj.AMask: {Flags: gc.SizeQ | gc.LeftRead | gc.RightWrite | gc.Conv},

	// Moves
	s390x.AMOVB & obj.AMask:  {Flags: gc.SizeB | gc.LeftRead | gc.RightWrite | gc.Move | gc.Conv},
	s390x.AMOVBZ & obj.AMask: {Flags: gc.SizeB | gc.LeftRead | gc.RightWrite | gc.Move | gc.Conv},
	s390x.AMOVH & obj.AMask:  {Flags: gc.SizeW | gc.LeftRead | gc.RightWrite | gc.Move | gc.Conv},
	s390x.AMOVHZ & obj.AMask: {Flags: gc.SizeW | gc.LeftRead | gc.RightWrite | gc.Move | gc.Conv},
	s390x.AMOVW & obj.AMask:  {Flags: gc.SizeL | gc.LeftRead | gc.RightWrite | gc.Move | gc.Conv},
	s390x.AMOVWZ & obj.AMask: {Flags: gc.SizeL | gc.LeftRead | gc.RightWrite | gc.Move | gc.Conv},
	s390x.AMOVD & obj.AMask:  {Flags: gc.SizeQ | gc.LeftRead | gc.RightWrite | gc.Move},
	s390x.AFMOVS & obj.AMask: {Flags: gc.SizeF | gc.LeftRead | gc.RightWrite | gc.Move | gc.Conv},
	s390x.AFMOVD & obj.AMask: {Flags: gc.SizeD | gc.LeftRead | gc.RightWrite | gc.Move},

	// Storage operations
	s390x.AMVC & obj.AMask: {Flags: gc.LeftRead | gc.LeftAddr | gc.RightWrite | gc.RightAddr},
	s390x.ACLC & obj.AMask: {Flags: gc.LeftRead | gc.LeftAddr | gc.RightRead | gc.RightAddr},
	s390x.AXC & obj.AMask:  {Flags: gc.LeftRead | gc.LeftAddr | gc.RightWrite | gc.RightAddr},
	s390x.AOC & obj.AMask:  {Flags: gc.LeftRead | gc.LeftAddr | gc.RightWrite | gc.RightAddr},
	s390x.ANC & obj.AMask:  {Flags: gc.LeftRead | gc.LeftAddr | gc.RightWrite | gc.RightAddr},

	// Jumps
	s390x.ABR & obj.AMask:      {Flags: gc.Jump | gc.Break},
	s390x.ABL & obj.AMask:      {Flags: gc.Call},
	s390x.ABEQ & obj.AMask:     {Flags: gc.Cjmp},
	s390x.ABNE & obj.AMask:     {Flags: gc.Cjmp},
	s390x.ABGE & obj.AMask:     {Flags: gc.Cjmp},
	s390x.ABLT & obj.AMask:     {Flags: gc.Cjmp},
	s390x.ABGT & obj.AMask:     {Flags: gc.Cjmp},
	s390x.ABLE & obj.AMask:     {Flags: gc.Cjmp},
	s390x.ACMPBEQ & obj.AMask:  {Flags: gc.Cjmp},
	s390x.ACMPBNE & obj.AMask:  {Flags: gc.Cjmp},
	s390x.ACMPBGE & obj.AMask:  {Flags: gc.Cjmp},
	s390x.ACMPBLT & obj.AMask:  {Flags: gc.Cjmp},
	s390x.ACMPBGT & obj.AMask:  {Flags: gc.Cjmp},
	s390x.ACMPBLE & obj.AMask:  {Flags: gc.Cjmp},
	s390x.ACMPUBEQ & obj.AMask: {Flags: gc.Cjmp},
	s390x.ACMPUBNE & obj.AMask: {Flags: gc.Cjmp},
	s390x.ACMPUBGE & obj.AMask: {Flags: gc.Cjmp},
	s390x.ACMPUBLT & obj.AMask: {Flags: gc.Cjmp},
	s390x.ACMPUBGT & obj.AMask: {Flags: gc.Cjmp},
	s390x.ACMPUBLE & obj.AMask: {Flags: gc.Cjmp},

	// Macros
	s390x.ACLEAR & obj.AMask: {Flags: gc.SizeQ | gc.LeftRead | gc.RightAddr | gc.RightWrite},

	// Load/store multiple
	s390x.ASTMG & obj.AMask: {Flags: gc.SizeQ | gc.LeftRead | gc.RightAddr | gc.RightWrite},
	s390x.ASTMY & obj.AMask: {Flags: gc.SizeL | gc.LeftRead | gc.RightAddr | gc.RightWrite},
	s390x.ALMG & obj.AMask:  {Flags: gc.SizeQ | gc.LeftAddr | gc.LeftRead | gc.RightWrite},
	s390x.ALMY & obj.AMask:  {Flags: gc.SizeL | gc.LeftAddr | gc.LeftRead | gc.RightWrite},

	obj.ARET & obj.AMask: {Flags: gc.Break},
}

func proginfo(p *obj.Prog) {
	info := &p.Info
	*info = progtable[p.As&obj.AMask]
	if info.Flags == 0 {
		gc.Fatalf("proginfo: unknown instruction %v", p)
	}

	if (info.Flags&gc.RegRead != 0) && p.Reg == 0 {
		info.Flags &^= gc.RegRead
		info.Flags |= gc.RightRead /*CanRegRead |*/
	}

	if (p.From.Type == obj.TYPE_MEM || p.From.Type == obj.TYPE_ADDR) && p.From.Reg != 0 {
		info.Regindex |= RtoB(int(p.From.Reg))
	}

	if (p.To.Type == obj.TYPE_MEM || p.To.Type == obj.TYPE_ADDR) && p.To.Reg != 0 {
		info.Regindex |= RtoB(int(p.To.Reg))
	}

	if p.From.Type == obj.TYPE_ADDR && p.From.Sym != nil && (info.Flags&gc.LeftRead != 0) {
		info.Flags &^= gc.LeftRead
		info.Flags |= gc.LeftAddr
	}

	switch p.As {
	// load multiple sets a range of registers
	case s390x.ALMG, s390x.ALMY:
		for r := p.Reg; r <= p.To.Reg; r++ {
			info.Regset |= RtoB(int(r))
		}
	// store multiple reads a range of registers
	case s390x.ASTMG, s390x.ASTMY:
		for r := p.From.Reg; r <= p.Reg; r++ {
			info.Reguse |= RtoB(int(r))
		}
	}
}
