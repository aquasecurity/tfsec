package ascii

import (
	"fmt"
	"image"
	"image/color"
	"image/gif"
	"time"

	"github.com/gdamore/tcell/v2"
)

type Renderer struct {
	screen tcell.Screen
	image  *gif.GIF
	width  int
	height int
	fill   bool
	ppcX   int
	ppcY   int
}

var ErrQuit = fmt.Errorf("user quit")

func (r *Renderer) init() error {
	screen, err := tcell.NewScreen()
	if err != nil {
		return err
	}
	if err := screen.Init(); err != nil {
		return err
	}
	r.screen = screen
	r.width, r.height = r.screen.Size()
	return nil
}

func (r *Renderer) SetFill(fill bool) {
	r.fill = fill
}

func (r *Renderer) close() {
	r.screen.Fini()
}

func (r *Renderer) Play() error {
	if err := r.init(); err != nil {
		return err
	}
	defer r.close()

	for {
		if err := r.cycleFrames(); err != nil {
			return err
		}
	}
}

func (r *Renderer) PlayOnce() error {
	if err := r.init(); err != nil {
		return err
	}
	defer r.close()

	return r.cycleFrames()
}

func (r *Renderer) cycleFrames() error {
	for i, frame := range r.image.Image {

		if err := r.drawFrame(frame, i); err != nil {
			return err
		}

		_ = r.screen.PostEvent(nil)
		switch ev := r.screen.PollEvent().(type) {
		case *tcell.EventResize:
			r.width, r.height = ev.Size()
		case *tcell.EventKey:
			if ev.Key() == tcell.KeyEscape {
				return ErrQuit
			}
			if ev.Key() == tcell.KeyRune {
				switch ev.Rune() {
				case 'q':
					return ErrQuit
				}
			}
		}

		delay := time.Duration(r.image.Delay[i]) * time.Millisecond * 10
		time.Sleep(delay)
	}
	return nil
}

func (r *Renderer) colourAtChar(i int, x int, y int, bounds image.Rectangle, disposal byte) (int32, int32, int32, bool) {

	var count uint64
	var tmpColor color.Color
	var ir, ig, ib, ia uint32
	var red, green, blue uint64 = 0, 0, 0

	background := r.image.Config.ColorModel.(color.Palette)[r.image.BackgroundIndex]

	for pX := x * r.ppcX; pX < (x*r.ppcX)+r.ppcX; pX++ {
		for pY := y * r.ppcY; pY < (y*r.ppcY)+r.ppcY; pY++ {
			if pX < bounds.Min.X || pY < bounds.Min.Y || pX > bounds.Max.X || pY > bounds.Max.Y {
				continue
			}

			ia = 0xffff

			tmpColor = r.image.Image[i].At(pX, pY)
			ir, ig, ib, ia = tmpColor.RGBA()

			if ia < 0x8888 {
				switch disposal {
				case gif.DisposalBackground:
					ir, ig, ib, ia = background.RGBA()
				case gif.DisposalPrevious:
					for index := i - 2; ia < 0x8888 && index >= 0; index-- {
						tmpColor = r.image.Image[index].At(pX, pY)
						ir, ig, ib, ia = tmpColor.RGBA()
					}
				case gif.DisposalNone:
					continue
				}
			}

			if ia < 0x8888 {
				continue
			}

			r := ir / 0xff
			g := ig / 0xff
			b := ib / 0xff

			if r > 0xff {
				r = 0xff
			}
			if g > 0xff {
				g = 0xff
			}
			if b > 0xff {
				b = 0xff
			}
			red += uint64(r)
			green += uint64(g)
			blue += uint64(b)
			count++
		}
	}

	if count == 0 {
		return 0, 0, 0, true
	}

	return int32(red / count), int32(green / count), int32(blue / count), count < (uint64(r.ppcX)*uint64(r.ppcY))/2
}

func (r *Renderer) drawFrame(img image.Image, i int) error {

	bounds := img.Bounds()
	_ = bounds
	width := r.image.Config.Width
	height := r.image.Config.Height

	termWidth := r.width
	termHeight := r.height

	if !r.fill {

		imgRatio := float64(width) / float64(height)
		termRatio := float64(r.width) / float64(r.height)

		if termRatio > imgRatio {
			termWidth = int(float64(termHeight) * imgRatio)
		} else {
			termHeight = int(float64(termWidth) / imgRatio)
		}

	}

	r.ppcX = width / termWidth
	r.ppcY = height / termHeight

	count := uint64(r.ppcX * r.ppcY)
	if count == 0 {
		return nil
	}

	var disposal byte
	if i == 0 {
		disposal = r.image.Disposal[len(r.image.Image)-1]
	} else {
		disposal = r.image.Disposal[i-1]
	}

	var cr, cg, cb int32
	var skip bool

	for x := 0; x < termWidth; x++ {
		for y := 0; y < termHeight; y++ {
			cr, cg, cb, skip = r.colourAtChar(i, x, y, bounds, disposal)
			if skip {
				continue
			}
			r.screen.SetCell(x, y, tcell.StyleDefault.Background(tcell.NewRGBColor(cr, cg, cb)), ' ')
		}
	}

	r.screen.Show()

	return nil
}
